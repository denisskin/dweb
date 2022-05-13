package vfs

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	testPrv = NewPrivateKeyBySeed("private-key-seed")
	testPub = testPrv.PublicKey()

	h1 = Header{
		{"Ver", []byte("1.0")},
		{"Title", []byte("Test header")},
		{"Hello-Phrase", []byte("Hello, 世界")},
	}
)

func init() {
	h1.Sign(testPrv)
}

func TestHeader_String(t *testing.T) {
	assert.Equal(t, ""+
		"Ver: 1.0\n"+
		"Title: Test header\n"+
		"Hello-Phrase: =?utf-8?b?SGVsbG8sIOS4lueVjA==?=\n"+
		"Public-Key: Ed25519,pms+pTAx/wOs+rx9Gy4wbdMWR/iz6MkEUBGlPF121GU=\n"+
		"Signature: =?utf-8?b?vNsD9iL4I3q4Ckle6g6CzlOfB9cuh0vOkivPV3E6HqcFF7M3a7iRYp5dZ6YR?= =?utf-8?b?c1y808LiJ+sGPC2eXkAROQkLCA==?="+
		"", h1.String())
}

func TestParseHeader(t *testing.T) {
	const strHeader = "" +
		"Ver: 1.0\n" +
		"Title: Test header\n" +
		"Hello-Phrase: =?utf-8?b?SGVsbG8sIOS4lueVjA==?=\n" +
		"Public-Key: Ed25519,pms+pTAx/wOs+rx9Gy4wbdMWR/iz6MkEUBGlPF121GU=\n" +
		"Signature: =?utf-8?b?vNsD9iL4I3q4Ckle6g6CzlOfB9cuh0vOkivPV3E6HqcFF7M3a7iRYp5dZ6YR?= =?utf-8?b?c1y808LiJ+sGPC2eXkAROQkLCA==?="

	h, err := ParseHeader(strHeader)

	assert.NoError(t, err)
	assert.Equal(t, h.String(), strHeader)
}

func TestHeader_Hash(t *testing.T) {

	hash := hex.EncodeToString(h1[:len(h1)-1].Hash())

	assert.Equal(t, "fad720402a8632cf3982497b9b508924bf92644ce75468622aee8f58bd743eba", hash)
}

func TestHeader_Verify(t *testing.T) {
	assert.True(t, h1.Verify())
}
