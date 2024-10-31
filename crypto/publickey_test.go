package crypto

import (
	"bytes"
	"testing"
)

func TestPublicKeyEncode(t *testing.T) {
	pub := NewPrivateKeyFromSeed("seed").PublicKey()

	assert(t, len(pub) == 32)
	assert(t, pub.Encode() == "Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY=")
}

func TestDecodePublicKey(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")

	pub := DecodePublicKey("Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY=")

	assert(t, pub != nil)
	assert(t, len(pub) == 32)
	assert(t, prv.PublicKey().Equal(pub))
}

func TestDecodePublicKey_fail(t *testing.T) {

	pub := DecodePublicKey("Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY1")

	assert(t, pub == nil)
}

func TestPrivateKey_Sign(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")

	sig1 := prv.Sign([]byte("test-message"))
	sig2 := prv.Sign([]byte("test-message"))

	assert(t, sig1 != nil)
	assert(t, len(sig1) == 64)
	assert(t, bytes.Equal(sig1, sig2))
}

func TestPublicKey_Verify(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()

	sig := prv.Sign([]byte("test-message"))

	assert(t, pub.Verify([]byte("test-message"), sig))   // OK
	assert(t, !pub.Verify([]byte("test-message1"), sig)) // corrupted message
	sig[0]++
	assert(t, !pub.Verify([]byte("test-message"), sig)) // corrupted signature
}

func BenchmarkPublicKey_Verify(b *testing.B) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()
	sig := prv.Sign([]byte("test-message"))

	for i := 0; i < b.N; i++ {
		assert(nil, pub.Verify([]byte("test-message"), sig)) // OK
	}
}

func BenchmarkPublicKey_DecodeOPublicKeyAndVerify(b *testing.B) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()
	sPub := pub.Encode()
	sig := prv.Sign([]byte("test-message"))

	for i := 0; i < b.N; i++ {
		pub2 := DecodePublicKey(sPub)
		assert(nil, pub2 != nil)
		assert(nil, pub2.Verify([]byte("test-message"), sig)) // OK
	}
}

func assert(t *testing.T, ok bool) {
	if !ok {
		t.Fatal("assertion failed")
	}
}
