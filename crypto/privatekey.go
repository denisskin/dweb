package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
)

type PrivateKey []byte

const (
	HashSize      = 32
	SignatureSize = ed25519.SignatureSize
)

func NewPrivateKeyBySeed(seed string) PrivateKey {
	return PrivateKey(ed25519.NewKeyFromSeed(Hash256([]byte(seed))))
}

func (prv PrivateKey) String() string {
	return prv.Encode()
}

func (prv PrivateKey) Encode() string {
	return "PRIVATE:Ed25519," + base64.StdEncoding.EncodeToString(prv)
}

func (prv PrivateKey) SubKey(name string) PrivateKey {
	return Hash256(Hash256(prv), Hash256([]byte(name)))
}

func (prv PrivateKey) PublicKey() PublicKey {
	return PublicKey(ed25519.PrivateKey(prv).Public().(ed25519.PublicKey))
}

func (prv PrivateKey) Sign(hash []byte) []byte {
	return ed25519.Sign([]byte(prv), hash)
}
