package vfs

import (
	"bytes"
	"github.com/denisskin/dweb/crypto"
	"github.com/denisskin/dweb/db"
	"io"
	"sync"
)

type fileSystem struct {
	pub   crypto.PublicKey
	db    db.Storage
	mx    sync.RWMutex
	nodes map[string]*fsNode
}

const dbKeyHeaders = "."

func OpenVFS(pub crypto.PublicKey, db db.Storage) (_ VFS, err error) {
	s := &fileSystem{
		pub: pub,
		db:  db,
	}
	return s, s.initDB()
}

func (f *fileSystem) setPartSize(size int64) {
	f.nodes["/"].Header.SetInt(headerPartSize, size)
}

//func (f *fileSystem) PublicKey() crypto.PublicKey {
//	return f.pub
//}

func (f *fileSystem) headers() (hh []Header) {
	for _, nd := range f.nodes {
		hh = append(hh, nd.Header)
	}
	sortHeaders(hh)
	return
}

func (f *fileSystem) Trace() {
	traceHeaders(f.headers())
}

func (f *fileSystem) initDB() (err error) {
	var hh []Header
	if err = db.GetJSON(f.db, dbKeyHeaders, &hh); err != nil {
		return
	}
	if hh == nil { // empty db
		hh = []Header{NewRootHeader(f.pub)}
	}
	f.nodes, err = indexTree(hh)
	return
}

func (f *fileSystem) fileHeader(path string) Header {
	if nd := f.nodes[path]; nd != nil {
		return nd.Header
	}
	return nil
}

func (f *fileSystem) root() Header {
	return f.nodes["/"].Header
}

func (f *fileSystem) FileHeader(path string) (Header, error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	if h := f.fileHeader(path); h != nil {
		return h.Copy(), nil
	}
	return nil, ErrNotFound
}

func (f *fileSystem) FileMerkleProof(path string) (hash, proof []byte, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	if f.nodes[path] == nil {
		return nil, nil, ErrNotFound
	}
	proof = f.nodes["/"].childrenMerkleProof(path)
	return proof[:crypto.HashSize], proof[crypto.HashSize:], nil
}

func (f *fileSystem) rootPartSize() int64 {
	if size := f.root().PartSize(); size > 0 {
		return size
	}
	return DefaultFilePartSize
}

func (f *fileSystem) FileParts(path string) (hashes [][]byte, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	h := f.fileHeader(path)
	if h == nil {
		err = ErrNotFound
		return
	}
	fl, err := f.db.Open(path)
	if err != nil {
		return
	}
	defer fl.Close()

	partSize := h.PartSize()
	if partSize == 0 {
		partSize = f.rootPartSize()
	}
	w := crypto.NewMerkleHash(partSize)
	_, err = io.Copy(w, fl)
	hashes = w.Leaves()
	return
}

func (f *fileSystem) Open(path string) (io.ReadSeekCloser, error) {
	return f.db.Open(path)
}

func (f *fileSystem) OpenAt(path string, offset int64) (io.ReadCloser, error) {
	r, err := f.db.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err = r.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return r, nil
}

//func (f *fileSystem) FileContent(path string, offset int64, size int) (data []byte, err error) {
//	data, err = f.db.Get(path)
//	if err == nil {
//		data = data[offset : int(offset)+size]
//	}
//	return
//}

func (f *fileSystem) ReadDir(path string) ([]Header, error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	if d := f.nodes[path]; d != nil && d.isDir() && !d.deleted() {
		return d.copyChildHeaders(), nil
	}
	return nil, ErrNotFound
}

func (f *fileSystem) Get(req string) (batch *Batch, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()

	return
}

func (f *fileSystem) GetBatch(ver int64) (batch *Batch, err error) {
	f.mx.RLock()
	defer f.mx.RUnlock()
	defer recoverErr(&err)

	root := f.nodes["/"]
	if root.Header.Ver() <= ver {
		return
	}
	w := newFilesReader()
	batch = &Batch{Body: w}
	root.walk(func(nd *fsNode) bool {
		if h := nd.Header; h.Ver() > ver {
			batch.Headers = append(batch.Headers, h.Copy())

			// TODO: rr[] = f.getReader(path) ...;  batch.Body = io.MultiReader(rr...)
			if size := h.FileSize(); size > 0 { // write file content to batch-body
				w.add(func() (io.ReadCloser, error) {
					return f.Open(nd.path)
				})
			}
		}
		return true
	})
	return
}

func (f *fileSystem) PutBatch(batch *Batch) (err error) {
	f.mx.Lock()
	defer f.mx.Unlock()
	defer recoverErr(&err)

	//--- verify batch ---
	assertBool(len(batch.Headers) > 0, "empty batch")
	sortHeaders(batch.Headers)

	//--- verify root-header ---
	r := f.root()
	b := batch.Root()

	assertBool(b.Get(headerProtocol) == DefaultProtocol, "unsupported Protocol")
	assertNoErr(ValidateHeader(b))
	assertBool(b.Path() == "/", "invalid batch-header Path")
	assertBool(b.Ver() > 0, "invalid batch-header Ver")
	assertBool(b.PartSize() == r.PartSize(), "invalid batch-header Part-Size")
	assertBool(!b.Created().IsZero(), "invalid batch-header Created")
	assertBool(!b.Updated().IsZero(), "invalid batch-header Updated")
	assertBool(b.Created().Equal(r.Created()) || r.Created().IsZero(), "invalid batch-header Created")
	assertBool(!b.Updated().Before(b.Created()), "invalid batch-header Updated")
	assertBool(VersionIsGreater(b, r), "invalid batch-header Ver")
	assertBool(!b.Deleted(), "invalid batch-header Deleted")
	assertBool(b.PublicKey().Equal(f.pub), "invalid batch-header Public-Key")
	assertBool(b.Verify(), "invalid batch-header Signature")

	//-----------
	curTree := f.nodes
	delFiles := map[string]bool{} // files to delete
	if b.Ver() == r.Ver() {       // if versions are equal than truncate db
		curTree = map[string]*fsNode{}
		for _, nd := range f.nodes {
			if !nd.isDir() && nd.Header.FileSize() > 0 {
				delFiles[nd.path] = true
			}
		}
	}

	//--- verify other headers ---
	updated := make(map[string]Header, len(batch.Headers))
	hh := make([]Header, 0, len(batch.Headers)+len(curTree))
	for _, h := range batch.Headers {
		assertNoErr(ValidateHeader(h))
		path := h.Path()
		hh = append(hh, h)
		updated[path] = h

		// verify batch-content
		if h.IsDir() || h.Deleted() { // dir or deleted file
			assertBool(!h.Has(headerFileMerkle), "invalid batch-header")
			assertBool(!h.Has(headerFileSize), "invalid batch-header")
		} else { // is not deleted file
			assertBool(h.FileSize() == 0 && !h.Has(headerFileMerkle) || h.FileSize() > 0 && len(h.FileMerkle()) == crypto.HashSize, "invalid batch-header")
		}
		if h.Deleted() { // delete all sub-files
			curTree[path].walk(func(nd *fsNode) bool {
				if !nd.isDir() && nd.Header.FileSize() > 0 {
					delFiles[nd.path] = true
				}
				return true
			})
		} else { // can`t restore deleted node
			nd := curTree[path]
			assertBool(nd == nil || !nd.Header.Deleted(), "invalid batch-header")
		}
	}
	//--- merge with existed headers ---
	var walk func(*fsNode)
	walk = func(nd *fsNode) {
		if nd == nil {
			return
		}
		h := updated[nd.path]
		if h == nil {
			hh = append(hh, nd.Header)
		}
		if h == nil || !h.Deleted() {
			for _, c := range nd.children {
				walk(c)
			}
		}
	}
	walk(curTree["/"])

	//--- update tree
	sortHeaders(hh)
	newTree, err := indexTree(hh)
	assertNoErr(err)

	//--- verify new root merkle and total-volume (Tree-Merkle, Tree-Volume headers)
	newMerkle := newTree["/"].childrenMerkleRoot()
	totalVolume := newTree["/"].totalVolume()
	assertBool(bytes.Equal(newMerkle, b.TreeMerkleRoot()), "invalid batch-header Tree-Merkle-Root")
	assertBool(totalVolume == b.GetInt(headerTreeVolume), "invalid batch-header Tree-Volume")

	rootPartSize := b.PartSize()
	//if rootPartSize == 0 {
	//	rootPartSize = DefaultFilePartSize
	//}

	//--- verify and put file content
	err = f.db.Execute(func(tx db.Transaction) (err error) {
		defer recoverErr(&err)

		for _, h := range batch.Headers {
			if hSize, hMerkle := h.FileSize(), h.FileMerkle(); hSize > 0 || len(hMerkle) != 0 {

				partSize := h.PartSize()
				if partSize == 0 {
					partSize = rootPartSize
				}
				assertBool(partSize > 0, "empty batch-header Part-Size")

				r := io.LimitReader(batch.Body, hSize)
				w := crypto.NewMerkleHash(partSize)
				err = tx.Put(h.Path(), io.TeeReader(r, w))
				assertNoErr(err)
				assertBool(w.Written() == hSize, "invalid batch-content")
				assertBool(bytes.Equal(w.Root(), h.FileMerkle()), "invalid batch-header Merkle")
				delete(delFiles, h.Path())

				//-------- v0
				//cont := make([]byte, int(hSize))
				//n, err := io.ReadFull(batch.Body, cont)
				//assertNoErr(err)
				//assertBool(int64(n) == hSize, "invalid batch-content")
				//
				//merkle, _, _ := crypto.ReadMerkleRoot(bytes.NewBuffer(cont), hSize, partSize)
				////assertBool(hSize == sz, "invalid batch-header Size")
				//assertBool(bytes.Equal(h.FileMerkle(), merkle), "invalid batch-header Merkle")
				//
				//err = tx.Put(h.Path(), bytes.NewBuffer(cont))
				//assertNoErr(err)
				//delete(delFiles, h.Path())

				//-----------
				// TODO: r := crypto.NewMerkleReader(batch.Body, hSize, h.PartSize())
				// tx.Put(key, r) // put reader
				// assertBool(bytes.Equal(h.Merkle(), r.MerkleRoot()))
				// assertBool(r.ReadSize() == size, "invalid batch-header Size")

				// todo: put content by hash (put if not exists, delete on error)
				//key:=fmt.Sprintf("X%x", merkle[:16])
				//exst, err:= f.db.Exists(key)
				//assertNoErr(err)
				//if !exst {
				//	err = f.db.Put(key, bytes.NewBuffer(cont))
				//	assertNoErr(err)
				//}
			}
		}

		//--- delete old files (???) -----
		for path := range delFiles {
			err = tx.Delete(path)
			assertNoErr(err)
		}
		//--- save to Storage
		return db.PutJSON(tx, dbKeyHeaders, hh)
	})

	assertNoErr(err)
	f.nodes = newTree
	return
}
