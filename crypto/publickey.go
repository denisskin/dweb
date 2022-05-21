package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

type PublicKey []byte

const PublicKeySize = ed25519.PublicKeySize

const publicKeyEncodingPrefix = "Ed25519,"

func (pub PublicKey) String() string {
	return pub.Encode()
}

func (pub PublicKey) Encode() string {
	return publicKeyEncodingPrefix + base64.StdEncoding.EncodeToString(pub)
}

func (pub PublicKey) Verify(hash, signature []byte) bool {
	return len(pub) == PublicKeySize &&
		len(hash) == HashSize &&
		len(signature) == SignatureSize &&
		ed25519.Verify([]byte(pub), hash, signature)
}

func DecodePublicKey(s string) PublicKey {
	s = strings.TrimPrefix(s, publicKeyEncodingPrefix)
	if p, _ := base64.StdEncoding.DecodeString(s); len(p) == PublicKeySize {
		return p
	}
	return nil
}
