package vfs

import (
	"bytes"
	"github.com/denisskin/dweb/crypto"
	"github.com/denisskin/dweb/db"
	"github.com/denisskin/dweb/db/memdb"
	"github.com/denisskin/dweb/vfs/test_data"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
	"time"
)

func TestMakeBatch(t *testing.T) {

	s := newMemVFS()

	//---------- batch-1 (init data)
	batch1 := makeTestBatch(s, "batch1")
	assert.True(t, len(batch1.Headers) > 1)
	assert.Equal(t, int64(1), batch1.Ver())
	trace("====== batch1", batch1)

	// apply batch
	err := s.PutBatch(batch1)
	assert.NoError(t, err)
	trace("====== db-1", s)

	// reapply the same batch - FAIL
	err = s.PutBatch(batch1)
	assert.Error(t, err)

	//------ repeat batch-1 (the same files; changed root-header only)
	batch1a := makeTestBatch(s, "batch1")
	assert.Equal(t, 1, len(batch1a.Headers))
	assert.Equal(t, int64(2), batch1a.Ver())

	err = s.PutBatch(batch1a)
	assert.NoError(t, err)
	trace("====== db-1a", s)

	//------- batch-2
	batch2 := makeTestBatch(s, "batch2")
	trace("====== batch2", batch2)
	assert.True(t, len(batch2.Headers) > 1)
	assert.Equal(t, int64(3), batch2.Ver())

	err = s.PutBatch(batch2)
	assert.NoError(t, err)
	trace("====== db-2", s)

	//------ make invalid batch
	badBatch := makeTestBatch(s, "batch3")
	badBatch.Headers[0].Set("Updated", "2020-01-03T00:00:01Z") // modify batch
	trace("====== invalid batch-1", badBatch)
	err = s.PutBatch(badBatch)
	assert.Error(t, err)

	//------ make invalid batch-2
	badBatch = makeTestBatch(s, "batch3")
	h := &badBatch.Headers[len(badBatch.Headers)-1]
	h.SetInt("Size", h.FileSize()+1) // modify batch-line-header Size for readme.txt file
	trace("====== invalid batch-2", badBatch)
	err = s.PutBatch(badBatch)
	assert.Error(t, err)

	//------ make invalid batch-3
	badBatch = makeTestBatch(s, "batch3")
	h = &badBatch.Headers[len(badBatch.Headers)-1]
	h.SetBytes("Merkle", append(h.FileMerkle(), 0)) // modify batch: modify header Merkle for last line (readme.txt)
	trace("====== invalid batch-3", badBatch)
	err = s.PutBatch(badBatch)
	assert.Error(t, err)

	//------ make invalid batch-4
	badBatch = makeTestBatch(s, "batch3")
	cont, _ := io.ReadAll(badBatch.Body)
	cont[len(cont)-1]++
	badBatch.Body = io.NopCloser(bytes.NewBuffer(cont)) // modify Content
	trace("====== invalid batch-4", badBatch)
	err = s.PutBatch(badBatch)
	assert.Error(t, err)

	//------ make invalid batch-5
	badBatch = makeTestBatch(s, "batch3")
	badBatch.Headers = badBatch.Headers[:len(badBatch.Headers)-1] // modify batch: delete last header
	trace("====== invalid batch-5", badBatch)
	err = s.PutBatch(badBatch)
	assert.Error(t, err)

	//------- batch-3
	batch3 := makeTestBatch(s, "batch3")
	trace("====== batch3", batch3)
	assert.True(t, len(batch3.Headers) > 1)
	assert.Equal(t, int64(4), batch3.Ver())

	err = s.PutBatch(batch3)
	assert.NoError(t, err)
	trace("====== db-3", s)

	//------- check result
	B, err := s.FileHeader("/B/")
	assert.NoError(t, err)
	assert.NotNil(t, B)
	assert.True(t, B.Deleted())

	B2, err := s.FileHeader("/B/2/")
	assert.Error(t, err)
	assert.Nil(t, B2)
}

func TestFileSystem_PutBatch_conflictBatches(t *testing.T) {

	//----- make two conflict batches. A.Ver == B.Ver && A.Updated == B.Updated
	batchA := makeTestBatch(newMemVFS(), "batch1")
	batchB := makeTestBatch(newMemVFS(), "batch1")
	batchB.Headers[0].Add("X", "x")
	batchB.Headers[0].Sign(testPrv)
	if bytes.Compare(batchA.Hash(), batchB.Hash()) > 0 {
		batchA, batchB = batchB, batchA
	}
	assert.True(t, batchA.Ver() == batchB.Ver())
	assert.True(t, batchA.Updated().Equal(batchB.Updated()))
	assert.True(t, bytes.Compare(batchA.Hash(), batchB.Hash()) < 0)

	//----- apply batch
	s := newMemVFS()
	err := s.PutBatch(batchA)
	assert.NoError(t, err)

	//----- apply alternative batch with great version. OK
	err = s.PutBatch(batchB)
	assert.NoError(t, err)

	//----- apply alternative batch with low version. FAIL
	err = s.PutBatch(batchA)
	assert.Error(t, err)
}

func TestFileSystem_GetBatch(t *testing.T) {

	s3 := applyBatch(newMemVFS(), "batch1", "batch2", "batch3")

	//--------
	s1 := applyBatch(newMemVFS(), "batch1")
	r1, err := s1.FileHeader("/")
	assert.NoError(t, err)

	// request batch from current version
	batch1, err := s3.GetBatch(r1.Ver())
	assert.NoError(t, err)
	assert.True(t, len(batch1.Headers) > 1)
	assert.Equal(t, int64(3), batch1.Root().Ver())

	err = s1.PutBatch(batch1)
	assert.NoError(t, err)
	assert.Equal(t, fsHeaders(s3), fsHeaders(s1))

	//--------
	s2 := applyBatch(newMemVFS(), "batch1")

	// request full batch (from 0version)
	batch2, err := s3.GetBatch(0)
	assert.NoError(t, err)
	assert.True(t, len(batch2.Headers) > 1)
	assert.Equal(t, int64(3), batch2.Root().Ver())

	err = s2.PutBatch(batch2)
	assert.NoError(t, err)
	assert.Equal(t, fsHeaders(s3), fsHeaders(s2))
}

func TestFileSystem_FileMerkleProof(t *testing.T) {
	s := applyBatch(newMemVFS(), "batch1")
	hh := fsHeaders(s)
	merkleRoot := hh[0].TreeMerkleRoot()

	for _, h := range hh[1:] {
		// make merkle proof for each file
		fileHash, fileProof, err := s.FileMerkleProof(h.Path())
		assert.NoError(t, err)
		assert.Equal(t, fileHash, h.Hash())
		assert.True(t, len(fileProof) > 0 && len(fileProof)%33 == 0)
		assert.Equal(t, 32, len(fileHash))

		// verify merkle-proof
		ok := crypto.VerifyMerkleProof(fileHash, merkleRoot, fileProof)
		assert.True(t, ok)

		if h.IsFile() {
			parts, err := s.FileParts(h.Path())
			assert.NoError(t, err)
			assert.Equal(t, h.FileMerkle(), crypto.MerkleRoot(parts...))
		}
	}
}

func makeTestBatch(vfs VFS, batchName string) *Batch {
	h0, err := vfs.FileHeader("/")
	assertNoErr(err)
	tBatch := h0.Updated().Add(time.Second)

	batch, err := MakeBatch(vfs, testPrv, test_data.FS(batchName), tBatch)
	assertNoErr(err)
	return batch
}

func fsHeaders(f VFS) (hh []Header) {
	return f.(*fileSystem).headers()
}

func newMemVFS() VFS {
	var t0, _ = time.Parse("2006-01-02 15:04:05", "2022-01-01 00:00:00")

	d := memdb.New()
	assertNoErr(d.Execute(func(tx db.Transaction) error { // init DB
		h0 := NewRootHeader(testPub)
		h0.SetTime("Created", t0)
		h0.SetTime("Updated", t0)
		h0.SetInt(headerPartSize, 1024)
		return db.PutJSON(tx, dbKeyHeaders, []Header{h0})
	}))
	f, err := OpenVFS(testPub, d)
	assertNoErr(err)
	return f
}

func applyBatch(f VFS, batchName ...string) VFS {
	for _, name := range batchName {
		assertNoErr(f.PutBatch(makeTestBatch(f, name)))
	}
	return f
}
