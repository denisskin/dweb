package vfs

import (
	"bytes"
	"github.com/denisskin/dweb/crypto"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"
)

type Batch struct {
	Headers []Header
	Body    io.Reader
}

func (b *Batch) Root() Header {
	return b.Headers[0]
}

func (b *Batch) BodySize() (n int64) {
	for _, h := range b.Headers {
		n += h.FileSize()
	}
	return
}

func (b *Batch) Trace() {
	traceHeaders(b.Headers)
}

func MakeBatch(vfs VFS, prv crypto.PrivateKey, src fs.FS, ts time.Time) (batch *Batch, err error) {
	defer recoverErr(&err)

	root, err := vfs.FileHeader("/")
	assertNoErr(err)
	ver := root.Ver() + 1       // new ver
	partSize := root.PartSize() //

	buf := bytes.NewBuffer(nil)
	batch = &Batch{Body: buf}

	inBatch := map[string]bool{}
	onDisk := map[string]bool{}

	var hh []Header
	var diskWalk func(string)
	diskWalk = func(path string) {
		var err error
		var dfsPath = path[1:] // trim prefix '/'
		var isDir = strings.HasSuffix(path, "/")
		h, err := vfs.FileHeader(path)
		if err == ErrNotFound {
			err = nil
		}
		assertNoErr(err)
		exists := h != nil
		if h == nil {
			h = Header{{headerPath, []byte(path)}}
		}
		onDisk[path] = true
		var fileMerkle, fileCont []byte
		var fileSize int64
		if !isDir {
			fileSize, fileMerkle, _, err = fsMerkleRoot(src, dfsPath, partSize)
			assertNoErr(err)
		}
		if path == "/" || !exists || !isDir && !bytes.Equal(h.GetBytes(headerFileMerkle), fileMerkle) { // not exists or changed
			h.SetInt(headerVer, ver) // set new version
			if !isDir {
				h.SetInt(headerFileSize, fileSize)
				h.SetBytes(headerFileMerkle, fileMerkle)
				fileCont, err = fs.ReadFile(src, dfsPath)
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
			dd, err := fs.ReadDir(src, dfsPath)
			assertNoErr(err)
			if len(dd) > MaxPathDirFilesCount {
				assertNoErr(ErrTooManyFiles)
			}
			sort.Slice(dd, func(i, j int) bool { // sort
				return pathLess(dd[i].Name(), dd[j].Name())
			})
			for _, f := range dd {
				if f.IsDir() {
					diskWalk(path + f.Name() + "/")
				} else {
					diskWalk(path + f.Name())
				}
			}
		}
	}
	diskWalk("/")

	//-- add old headers to batch
	var vfsWalk func(Header)
	vfsWalk = func(h Header) {
		path := h.Path()
		if !onDisk[path] { // delete node
			h = Header{{headerPath, []byte(path)}}
			h.SetInt(headerVer, ver)
			h.SetInt(headerDeleted, 1)
			hh = append(hh, h)
			batch.Headers = append(batch.Headers, h)
			return // skip all child nodes
		}
		if !inBatch[path] {
			hh = append(hh, h)
		}
		ff, err := vfs.ReadDir(path)
		if err == ErrNotFound {
			err = nil
		}
		assertNoErr(err)
		for _, h := range ff {
			vfsWalk(h)
		}
	}
	vfsWalk(root)

	//-- calc new batch merkle
	sortHeaders(batch.Headers)
	sortHeaders(hh)
	newTree, err := indexTree(hh)
	assertNoErr(err)
	ndRoot := newTree["/"]

	//--- set merkle + sign
	newRoot := &batch.Headers[0]
	if !newRoot.Has(headerCreated) {
		newRoot.SetTime(headerCreated, ts)
	}
	newRoot.SetTime(headerUpdated, ts)
	newRoot.SetInt(headerTreeVolume, ndRoot.totalVolume())
	newRoot.SetBytes(headerTreeMerkleRoot, ndRoot.childrenMerkleRoot())
	newRoot.Sign(prv)
	return
}

func fsMerkleRoot(dfs fs.FS, path string, partSize int64) (size int64, merkle []byte, hashes [][]byte, err error) {
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
	merkle, hashes, err = crypto.ReadMerkleRoot(f, size, partSize)
	return
}
