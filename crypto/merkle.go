package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"
)

const (
	OpLHash = 0
	OpRHash = 1
)

func MerkleRoot(hash ...[]byte) []byte {
	return MakeMerkleRoot(len(hash), func(i int) []byte {
		return hash[i]
	})
}

func MakeMerkleRoot(n int, itemHash func(int) []byte) []byte {
	return merkleRootFn(0, n, itemHash)
}

func merkleRootFn(offset, n int, itemHash func(int) []byte) []byte {
	if n == 0 {
		return nil
	} else if n == 1 {
		return itemHash(offset)
	}
	i := merkleMiddle(n)
	return Hash256(
		merkleRootFn(offset, i, itemHash),
		merkleRootFn(offset+i, n-i, itemHash),
	)
}

func MakeMerkleProof(hashes [][]byte, i int) (buf []byte) {
	n := len(hashes)
	if i < 0 || i >= n {
		panic("invalid tree")
	}
	if n == 1 {
		return hashes[0]
	}
	if i2 := merkleMiddle(n); i < i2 { // arg=HASH(arg|op)
		return MerkleProofAppend(
			MakeMerkleProof(hashes[:i2], i),
			OpRHash,
			MerkleRoot(hashes[i2:]...),
		)
	} else { // arg=HASH(op|arg)
		return MerkleProofAppend(
			MakeMerkleProof(hashes[i2:], i-i2),
			OpLHash,
			MerkleRoot(hashes[:i2]...),
		)
	}
}

func MerkleProofAppend(proof []byte, op byte, hash []byte) []byte {
	return append(append(proof, op), hash...)
}

func merkleMiddle(n int) (i int) {
	for i = 1; (i << 1) < n; i <<= 1 {
	}
	return
}

func VerifyMerkleProof(hash, root, proof []byte) bool {
	const opSize = HashSize + 1
	for n := len(proof); n > 0; n -= opSize {
		if n < opSize {
			return false
		}
		switch op, arg := proof[0], proof[1:opSize]; op {
		case OpRHash:
			hash = Hash256(hash, arg)
		case OpLHash:
			hash = Hash256(arg, hash)
		default:
			return false
		}
		proof = proof[opSize:]
	}
	return bytes.Equal(hash, root)
}

func ReadMerkleRoot(r io.Reader, size, partSize int64) (merkle []byte, hashes [][]byte, err error) {
	hashes = make([][]byte, 0, countParts(size, partSize))
	for size > 0 {
		w := sha256.New()
		if n, err := io.CopyN(w, r, min64(partSize, size)); err != nil {
			return nil, nil, err
		} else {
			size -= n
		}
		hashes = append(hashes, w.Sum(nil))
	}
	merkle = MerkleRoot(hashes...)
	return
}

func countParts(size, partSize int64) int {
	n := size / partSize
	if size/partSize != 0 {
		n++
	}
	return int(n)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
