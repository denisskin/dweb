package crypto

import (
	"crypto/sha256"
)

func Hash256(vv ...[]byte) []byte {
	h := sha256.New()
	for _, v := range vv {
		h.Write(v)
	}
	return h.Sum(nil)
}
