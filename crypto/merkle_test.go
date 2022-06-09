package crypto

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io"
	"math/rand"
	"testing"
)

func TestNewMerkleHash(t *testing.T) {

	const partSize = 1 << 20 // 1MiB
	hash := NewMerkleHash(partSize)

	// write random data
	n, err := io.Copy(hash, io.LimitReader(rand.New(rand.NewSource(0)), 20e6))

	assert.Equal(t, int64(20e6), n)
	assert.NoError(t, err)
	assert.Equal(t, 20, len(hash.Leaves()))
	assert.Equal(t, "1504aceff010d04d5ee597bf33d2195491d3534b5e28e9c08259bc4d50373490", hex.EncodeToString(hash.Root()))
}

func TestNewMerkleHash_withZero(t *testing.T) {

	hash := NewMerkleHash(0) // is equivalent of NewHash()

	// write random data
	n, err := io.Copy(hash, io.LimitReader(rand.New(rand.NewSource(0)), 20e6))

	assert.Equal(t, int64(20e6), n)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(hash.Leaves()))
	assert.Equal(t, "9c9f54aca340d76dd36acd53069805bed7aca84f28b1a6bc2c7d27f7f06fac20", hex.EncodeToString(hash.Root()))
}

func TestNewHash(t *testing.T) {

	hash := NewHash()

	// write random data
	n, err := io.Copy(hash, io.LimitReader(rand.New(rand.NewSource(0)), 20e6))

	assert.Equal(t, int64(20e6), n)
	assert.NoError(t, err)
	assert.Equal(t, "9c9f54aca340d76dd36acd53069805bed7aca84f28b1a6bc2c7d27f7f06fac20", hex.EncodeToString(hash.Sum(nil)))
}
