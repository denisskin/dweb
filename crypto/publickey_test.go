package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPublicKeyEncode(t *testing.T) {
	pub := NewPrivateKeyFromSeed("seed").PublicKey()

	assert.Equal(t, 32, len(pub))
	assert.Equal(t, "Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY=", pub.Encode())
}

func TestDecodePublicKey(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")

	pub := DecodePublicKey("Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY=")

	assert.NotNil(t, pub)
	assert.Equal(t, 32, len(pub))
	assert.True(t, prv.PublicKey().Equal(pub))
}

func TestDecodePublicKey_fail(t *testing.T) {

	pub := DecodePublicKey("Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY1")

	assert.Nil(t, pub)
}

func TestPrivateKey_Sign(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")

	sig1 := prv.Sign([]byte("test-message"))
	sig2 := prv.Sign([]byte("test-message"))

	assert.NotNil(t, sig1)
	assert.Equal(t, 64, len(sig1))
	assert.Equal(t, sig1, sig2)
}

func TestPublicKey_Verify(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()

	sig := prv.Sign([]byte("test-message"))

	assert.True(t, pub.Verify([]byte("test-message"), sig))   // OK
	assert.False(t, pub.Verify([]byte("test-message1"), sig)) // corrupted message
	sig[0]++
	assert.False(t, pub.Verify([]byte("test-message"), sig)) // corrupted signature
}
