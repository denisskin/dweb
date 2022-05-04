package vfs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"io/fs"
	"strings"
)

type (
	PrivateKey = ed25519.PrivateKey
	PublicKey  = ed25519.PublicKey
)

const (
	HashSize      = 32
	PublicKeySize = ed25519.PublicKeySize
	SignatureSize = ed25519.SignatureSize
)

const publicKeyPrefix = "Ed25519,"

const (
	OpLHash = 0
	OpRHash = 1
)

func NewPrivateKeyBySeed(seed string) PrivateKey {
	return ed25519.NewKeyFromSeed(hash256([]byte(seed)))
}

func hash256(vv ...[]byte) []byte {
	h := sha256.New()
	for _, v := range vv {
		h.Write(v)
	}
	return h.Sum(nil)
}

func merkleRoot(hash ...[]byte) []byte {
	return merkleRootFn(0, len(hash), func(i int) []byte {
		return hash[i]
	})
}

func merkleRootFn(offset, n int, itemHash func(int) []byte) []byte {
	if n == 0 {
		return nil
	} else if n == 1 {
		return itemHash(offset)
	}
	i := merkleMiddle(n)
	return hash256(
		merkleRootFn(offset, i, itemHash),
		merkleRootFn(offset+i, n-i, itemHash),
	)
}

func makeMerkleProof(hashes [][]byte, i int) (buf []byte) {
	n := len(hashes)
	if i < 0 || i >= n {
		panic("invalid tree")
	}
	if n == 1 {
		return hashes[0]
	}
	if i2 := merkleMiddle(n); i < i2 { // arg=HASH(arg|op)
		return merkleProofAppend(
			makeMerkleProof(hashes[:i2], i),
			OpRHash,
			merkleRoot(hashes[i2:]...),
		)
	} else { // arg=HASH(op|arg)
		return merkleProofAppend(
			makeMerkleProof(hashes[i2:], i-i2),
			OpLHash,
			merkleRoot(hashes[:i2]...),
		)
	}
}

func merkleProofAppend(proof []byte, op byte, hash []byte) []byte {
	return append(append(proof, op), hash...)
}

func merkleMiddle(n int) (i int) {
	for i = 1; (i << 1) < n; i <<= 1 {
	}
	return
}

func EncodePublicKey(pub PublicKey) string {
	return publicKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

func DecodePublicKey(s string) PublicKey {
	s = strings.TrimPrefix(s, publicKeyPrefix)
	if p, _ := base64.StdEncoding.DecodeString(s); len(p) == PublicKeySize {
		return p
	}
	return nil
}

func Verify(pub PublicKey, hash, signature []byte) bool {
	return len(pub) == PublicKeySize &&
		len(hash) == HashSize &&
		len(signature) == SignatureSize &&
		ed25519.Verify(pub, hash, signature)
}

func Sign(prv PrivateKey, hash []byte) []byte {
	return ed25519.Sign(prv, hash)
}

func VerifyMerkleProof(hash, root, proof []byte) bool {
	const opSize = HashSize + 1
	for n := len(proof); n > 0; n -= opSize {
		if n < opSize {
			return false
		}
		switch op, arg := proof[0], proof[1:opSize]; op {
		case OpRHash:
			hash = hash256(hash, arg)
		case OpLHash:
			hash = hash256(arg, hash)
		default:
			return false
		}
		proof = proof[opSize:]
	}
	return bytes.Equal(hash, root)
}

// todo: add readMerkle(r io.Reader, partSize int64) (size int64, merkle []byte, err error)

func getPartHashes(r io.Reader, fileSize, partSize int64) (hashes [][]byte, err error) {
	for fileSize > 0 {
		w := sha256.New()
		if n, err := io.CopyN(w, r, min64(partSize, fileSize)); err != nil {
			return nil, err
		} else {
			fileSize -= n
		}
		hashes = append(hashes, w.Sum(nil))
	}
	return
}

func pathLess(a, b string) bool {
	// TODO: optimize
	A := strings.Split(a, "/")
	B := strings.Split(b, "/")
	nB := len(B)
	for i, Ai := range A {
		if nB < i+1 {
			return false
		} else if Ai != B[i] {
			return Ai < B[i]
		}
	}
	return true
}

//func fsFileContent(dfs fs.FS, path string, partSize int64) (cont, merkle []byte, size int64, err error) {
//	if cont, err = fs.ReadFile(dfs, path); err != nil {
//		return
//	}
//	size = int64(len(cont))
//	hh, _ := getPartHashes(bytes.NewReader(cont), size, partSize)
//	merkle = merkleRoot(hh...)
//	return
//}

func contentMerkle(content []byte, partSize int64) (size int64, merkle []byte) {
	size = int64(len(content))
	hh, _ := getPartHashes(bytes.NewBuffer(content), size, partSize)
	merkle = merkleRoot(hh...)
	return
}

//func fileMerkle(r io.Reader, size, partSize int64) (merkle []byte, err error) {
//	//.........
//}

func fsFileMerkle(dfs fs.FS, path string, partSize int64) (size int64, merkle []byte, err error) {
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
	hh, err := getPartHashes(f, size, partSize)
	if err != nil {
		return
	}
	merkle = merkleRoot(hh...)
	return
}
