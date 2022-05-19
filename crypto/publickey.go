package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

type PublicKey []byte

const publicKeyPrefix = "Ed25519,"

func (pub PublicKey) String() string {
	return pub.Encode()
}

func (pub PublicKey) Encode() string {
	return publicKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

func (pub PublicKey) Verify(hash, signature []byte) bool {
	return len(pub) == PublicKeySize &&
		len(hash) == HashSize &&
		len(signature) == SignatureSize &&
		ed25519.Verify([]byte(pub), hash, signature)
}

func DecodePublicKey(s string) PublicKey {
	s = strings.TrimPrefix(s, publicKeyPrefix)
	if p, _ := base64.StdEncoding.DecodeString(s); len(p) == PublicKeySize {
		return p
	}
	return nil
}
