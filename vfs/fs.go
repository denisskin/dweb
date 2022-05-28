package vfs

import (
	"bytes"
	"github.com/denisskin/dweb/crypto"
	"github.com/denisskin/dweb/db"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"
)

type fileSystem struct {
	pub   crypto.PublicKey
	db    db.Storage
	mx    sync.Mutex
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

func (f *fileSystem) setPieceSize(size int64) {
	f.nodes["/"].Header.SetInt(headerPieceSize, size)
}

func (f *fileSystem) PublicKey() crypto.PublicKey {
	return f.pub
}

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

func (f *fileSystem) FileHeader(path string) (h Header, err error) {
	if h = f.fileHeader(path); h == nil {
		err = ErrNotFound
	}
	return
}

func (f *fileSystem) FileMerkleProof(path string) (hash, proof []byte, err error) {
	if f.nodes[path] == nil {
		return nil, nil, ErrNotFound
	}
	proof = f.nodes["/"].childrenMerkleProof(path)
	return proof[:crypto.HashSize], proof[crypto.HashSize:], nil
}

func (f *fileSystem) rootPieceSize() int64 {
	if size := f.root().PieceSize(); size > 0 {
		return size
	}
	return DefaultFilePieceSize
}

func (f *fileSystem) FilePieces(path string) (hashes [][]byte, err error) {
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

	pieceSize := h.PieceSize()
	if pieceSize == 0 {
		pieceSize = f.rootPieceSize()
	}
	_, hashes, err = crypto.ReadMerkleRoot(fl, h.FileSize(), pieceSize)
	return
}

func (f *fileSystem) Open(path string) (File, error) {
	return f.db.Open(path)
}

//func (f *fileSystem) FileContent(path string, offset int64, size int) (data []byte, err error) {
//	data, err = f.db.Get(path)
//	if err == nil {
//		data = data[offset : int(offset)+size]
//	}
//	return
//}

func (f *fileSystem) ReadDir(path string) ([]Header, error) {
	if d := f.nodes[path]; d != nil && d.isDir() && !d.deleted() {
		return d.childHeaders(), nil
	}
	return nil, ErrNotFound
}

func (f *fileSystem) GetBatch(ver int64) (batch *Batch, err error) {
	defer recoverErr(&err)

	root := f.nodes["/"]
	if root.Header.Ver() <= ver {
		return
	}
	w := bytes.NewBuffer(nil)
	batch = &Batch{Body: w}
	root.walk(func(nd *fsNode) bool {
		if h := nd.Header; h.Ver() > ver {
			batch.Headers = append(batch.Headers, h.Copy())

			// TODO: rr[] = f.getReader(path) ...;  batch.Body = io.MultiReader(rr...)
			if size := h.FileSize(); size > 0 { // write file content to batch-body
				fl, err := f.Open(nd.path)
				assertNoErr(err)
				defer fl.Close()
				_, err = io.CopyN(w, fl, size)
				assertNoErr(err)
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
	assertBool(b.Path() == "/", "invalid batch-header Path")
	assertBool(b.Ver() > 0, "invalid batch-header Ver")
	assertBool(b.Ver() > r.Ver(), "invalid batch-header Ver")
	assertBool(b.PieceSize() == r.PieceSize(), "invalid batch-header Piece-Size")
	assertBool(!b.Created().IsZero(), "invalid batch-header Created")
	assertBool(!b.Updated().IsZero(), "invalid batch-header Updated")
	assertBool(b.Created().Unix() == r.Created().Unix() || r.Created().IsZero(), "invalid batch-header Created")
	assertBool(b.Updated().Unix() >= b.Created().Unix(), "invalid batch-header Updated")
	assertBool(b.Updated().Unix() > r.Updated().Unix(), "invalid batch-header Updated")
	assertBool(!b.Deleted(), "invalid batch-header Deleted")
	assertBool(bytes.Equal(b.PublicKey(), f.pub), "invalid batch-header PublicKey")
	assertBool(b.Verify(), "invalid batch-header Signature")
	assertNoErr(validateRoot(b, f.pub))

	//--- verify other headers ---
	updated := make(map[string]Header, len(batch.Headers))
	hh := make([]Header, 0, len(batch.Headers)+len(f.nodes))

	for _, h := range batch.Headers {
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
		if !h.Deleted() { // can`t restore deleted node
			nd := f.nodes[path]
			assertBool(nd == nil || !nd.Header.Deleted(), "invalid batch-header")
		}
	}
	//--- merge with existed headers ---
	var walk func(*fsNode)
	walk = func(nd *fsNode) {
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
	walk(f.nodes["/"])

	//--- update tree
	sortHeaders(hh)
	newNodes, err := indexTree(hh)
	assertNoErr(err)

	//--- verify new root merkle and total-volume (Tree-Merkle, Tree-Volume headers)
	newMerkle := newNodes["/"].childrenMerkleRoot()
	totalVolume := newNodes["/"].totalVolume()
	assertBool(bytes.Equal(newMerkle, b.TreeMerkleRoot()), "invalid batch-header Tree-Merkle-Root")
	assertBool(totalVolume == b.GetInt(headerTreeVolume), "invalid batch-header Tree-Volume")

	rootPieceSize := b.PieceSize()
	//if rootPieceSize == 0 {
	//	rootPieceSize = DefaultFilePieceSize
	//}

	//--- verify and put file content
	err = f.db.Execute(func(tx db.Transaction) (err error) {
		defer recoverErr(&err)

		for _, h := range batch.Headers {
			if hSize, hMerkle := h.FileSize(), h.FileMerkle(); hSize > 0 || len(hMerkle) != 0 {

				pieceSize := h.PieceSize()
				if pieceSize == 0 {
					pieceSize = rootPieceSize
				}
				assertBool(pieceSize > 0, "empty batch-header Piece-Size")

				cont := make([]byte, int(hSize))
				n, err := io.ReadFull(batch.Body, cont)
				assertNoErr(err)
				assertBool(int64(n) == hSize, "invalid batch-content")

				merkle, _, _ := crypto.ReadMerkleRoot(bytes.NewBuffer(cont), hSize, pieceSize)
				//assertBool(hSize == sz, "invalid batch-header Size")
				assertBool(bytes.Equal(h.FileMerkle(), merkle), "invalid batch-header Merkle")

				err = tx.Put(h.Path(), bytes.NewBuffer(cont))
				assertNoErr(err)

				// TODO: r := crypto.NewMerkleReader(batch.Body, hSize, h.PieceSize())
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
		//--- save to Storage
		return db.PutJSON(tx, dbKeyHeaders, hh)
	})

	assertNoErr(err)
	f.nodes = newNodes
	return
}

func (f *fileSystem) MakeBatch(prv crypto.PrivateKey, dfs fs.FS, ts time.Time) (batch *Batch, err error) {
	defer recoverErr(&err)

	h0 := f.nodes["/"].Header
	ver := h0.Ver() + 1         // new ver
	pieceSize := h0.PieceSize() //

	buf := bytes.NewBuffer(nil)
	batch = &Batch{Body: buf}

	var hh []Header
	var inBatch = map[string]bool{}
	var onDisk = make(map[string]bool, len(f.nodes))

	var walkOnDisk func(string)
	walkOnDisk = func(path string) {
		var err error
		var dfsPath = path[1:] // trim prefix '/'
		var isDir = strings.HasSuffix(path, "/")
		var h Header
		var exists bool
		var nd = f.nodes[path]
		if nd != nil { // file is exists
			h, exists = nd.Header.Copy(), true
		} else {
			h = Header{{headerPath, []byte(path)}}
		}
		onDisk[path] = true
		var fileMerkle, fileCont []byte
		var fileSize int64
		if !isDir {
			fileSize, fileMerkle, _, err = fsMerkleRoot(dfs, dfsPath, pieceSize)
			assertNoErr(err)
		}
		if path == "/" || !exists || !isDir && !bytes.Equal(h.GetBytes(headerFileMerkle), fileMerkle) { // not exists or changed
			h.SetInt(headerVer, ver) // set new version
			if !isDir {
				h.SetInt(headerFileSize, fileSize)
				h.SetBytes(headerFileMerkle, fileMerkle)
				fileCont, err = fs.ReadFile(dfs, dfsPath)
				assertNoErr(err)
				_, err = buf.Write(fileCont)
				assertNoErr(err)
			}
			batch.Headers = append(batch.Headers, h)
			inBatch[path], hh = true, append(hh, h)
		}
		if isDir { //- read dir
			if dfsPath == "" {
				dfsPath = "."
			}
			dfsPath = strings.TrimSuffix(dfsPath, "/")
			dd, err := fs.ReadDir(dfs, dfsPath)
			assertNoErr(err)
			if len(dd) > MaxPathDirFilesCount {
				assertNoErr(ErrTooManyFiles)
			}
			sort.Slice(dd, func(i, j int) bool { // sort
				return pathLess(dd[i].Name(), dd[j].Name())
			})
			for _, f := range dd {
				if f.IsDir() {
					walkOnDisk(path + f.Name() + "/")
				} else {
					walkOnDisk(path + f.Name())
				}
			}
		}
	}
	walkOnDisk("/")

	//-- add old headers to batch
	fSort := false
	f.nodes["/"].walk(func(nd *fsNode) bool {
		if !onDisk[nd.path] { // delete node
			fSort = true
			var h = Header{{headerPath, []byte(nd.path)}}
			h.SetInt(headerVer, ver)
			h.SetInt(headerDeleted, 1)
			hh = append(hh, h)
			batch.Headers = append(batch.Headers, h)
			return false // skip all child nodes
		}
		if !inBatch[nd.path] {
			hh = append(hh, nd.Header)
		}
		return true
	})
	if fSort {
		sortHeaders(batch.Headers)
	}

	//-- calc new batch merkle
	sortHeaders(hh)
	newTree, err := indexTree(hh)
	assertNoErr(err)
	ndRoot := newTree["/"]

	//--- set merkle + sign
	hRoot := &batch.Headers[0]
	if !hRoot.Has(headerCreated) {
		hRoot.SetTime(headerCreated, ts)
	}
	hRoot.SetTime(headerUpdated, ts)
	hRoot.SetInt(headerTreeVolume, ndRoot.totalVolume())
	hRoot.SetBytes(headerTreeMerkleRoot, ndRoot.childrenMerkleRoot())
	hRoot.Sign(prv)
	return batch, nil
}

func fsMerkleRoot(dfs fs.FS, path string, pieceSize int64) (size int64, merkle []byte, hashes [][]byte, err error) {
	f, err := dfs.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	size = st.Size()
	merkle, hashes, err = crypto.ReadMerkleRoot(f, size, pieceSize)
	return
}
