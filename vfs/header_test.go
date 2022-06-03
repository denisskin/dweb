package vfs

import (
	"encoding/hex"
	"encoding/json"
	"github.com/denisskin/dweb/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	testPrv = crypto.NewPrivateKeyBySeed("private-key-seed")
	testPub = testPrv.PublicKey()

	testHeaders = []Header{{
		{"Ver", []byte("1")},
		{"Title", []byte("Hello, 世界")},
		{"Description", []byte("Test header")},
		{"Path", []byte("/")},
		{"Created", []byte("2022-01-01T01:02:03Z")},
		{"Updated", []byte("2022-01-01T01:02:03Z")},
		{"Part-Size", []byte("1024")},
	}, {
		{"Ver", []byte("1")},
		{"Path", []byte("/dir/")},
	}, {
		{"Ver", []byte("2")},
		{"Path", []byte("/dir/abc.txt")},
		{"Size", []byte("3")},
		{"Merkle", crypto.Hash256([]byte("ABC"))},
	}}
)

const testHeadersJSON = `[
	{
		"Ver":"1",
		"Title":"base64,SGVsbG8sIOS4lueVjA",
		"Description":"Test header",
		"Path":"/",
		"Created":"2022-01-01T01:02:03Z",
		"Updated":"2022-01-01T01:02:03Z",
		"Part-Size":"1024",
		"Public-Key":"Ed25519,pms+pTAx/wOs+rx9Gy4wbdMWR/iz6MkEUBGlPF121GU=",
		"Signature":"base64,RawwRUohAE9zjGFAGurDPp0ceZvKgDjTByQ5A4/JrLjYqEyQFA+6Ynu9JPCdrK5KxCoEqeBdKRKAd/ZmDQ5dAA"
	},{
		"Ver":"1",
		"Path":"/dir/"
	},{
		"Ver":"2",
		"Path":"/dir/abc.txt",
		"Size":"3",
		"Merkle":"base64,tdQEXD9Gb6kf4sxqvnkjKhpXzfEE96JucW4KHieJ33g"
	}
]`

func init() {
	testHeaders[0].Sign(testPrv)
}

func TestValidateHeader(t *testing.T) {
	for _, h := range testHeaders {
		err := ValidateHeader(h)
		assert.NoError(t, err)
	}
}

func TestHeader_String(t *testing.T) {
	assert.Equal(t, `{`+
		`"Ver":"1",`+
		`"Title":"base64,SGVsbG8sIOS4lueVjA",`+
		`"Description":"Test header",`+
		`"Path":"/",`+
		`"Created":"2022-01-01T01:02:03Z",`+
		`"Updated":"2022-01-01T01:02:03Z",`+
		`"Part-Size":"1024",`+
		`"Public-Key":"Ed25519,pms+pTAx/wOs+rx9Gy4wbdMWR/iz6MkEUBGlPF121GU=",`+
		`"Signature":"base64,RawwRUohAE9zjGFAGurDPp0ceZvKgDjTByQ5A4/JrLjYqEyQFA+6Ynu9JPCdrK5KxCoEqeBdKRKAd/ZmDQ5dAA"`+
		`}`,
		testHeaders[0].String(),
	)
}

func TestHeader_MarshalJSON(t *testing.T) {

	data, err := json.Marshal(testHeaders)

	assert.NoError(t, err)
	assert.JSONEq(t, testHeadersJSON, string(data))
}

func TestHeader_UnmarshalJSON(t *testing.T) {

	var hh []Header
	err := json.Unmarshal([]byte(testHeadersJSON), &hh)

	assert.NoError(t, err)
	assert.Equal(t, testHeaders, hh)
}

func TestHeader_Hash(t *testing.T) {

	h0 := testHeaders[0]
	hash := hex.EncodeToString(h0[:len(h0)-1].Hash())

	assert.Equal(t, "c4f2bda7321becfbae65838c9a34d78754fec160ee918b4361fcf6477f1b8ad9", hash)
}

func TestHeader_Verify(t *testing.T) {
	assert.True(t, testHeaders[0].Verify())
}
