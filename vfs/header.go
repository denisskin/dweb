package vfs

import (
	"bytes"
	"encoding/json"
	"mime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Header []KeyValue

type KeyValue struct {
	Key   string `json:"key"`   //
	Value []byte `json:"value"` //
}

const (
	HeaderVer       = "Ver"        // file-version
	HeaderDeleted   = "Deleted"    //
	HeaderPublicKey = "Public-Key" //
	HeaderSignature = "Signature"  //
)

func initRootHeader(pub PublicKey) (h Header) {
	h.Add("Protocol", DefaultProtocol)
	h.Add("Path", "/")
	h.AddInt("Ver", 0)
	h.SetPublicKey(pub)
	return
}

const headerKeyChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."

func isValidHeaderKey(key string) bool {
	return containOnly(key, headerKeyChars)
}

func encodeHeaderValue(v []byte) string {
	return mime.BEncoding.Encode("utf-8", string(v))
}

var headerValueDecoder mime.WordDecoder

func decodeHeaderValue(v string) ([]byte, error) {
	v, err := headerValueDecoder.DecodeHeader(v)
	return []byte(v), err
}

func decodeHeaderKey(v string) (string, error) {
	v, err := headerValueDecoder.DecodeHeader(v)
	return v, err
}

func (v KeyValue) Hash() []byte {
	return merkleRoot(
		hash256([]byte(v.Key)),
		hash256(v.Value),
	)
}

func (v KeyValue) String() string {
	return encodeHeaderValue([]byte(v.Key)) + ": " + encodeHeaderValue(v.Value)
}

func (v KeyValue) JSON() string {
	return "{" + toJSON(v.Key) + ":" + toJSON(v.Value) + "}"
}

func (v KeyValue) MarshalJSON() ([]byte, error) {
	return []byte(v.JSON()), nil
}

func (v *KeyValue) UnmarshalJSON(data []byte) (err error) {
	var vv map[string][]byte
	if err = json.Unmarshal(data, &vv); err == nil && vv != nil {
		for k, val := range vv {
			v.Key, v.Value = k, val
		}
	}
	return err
}

//-------------------------------------------------------------

func (h Header) Copy() Header {
	h1 := make(Header, len(h))
	copy(h1, h)
	return h1
}

func (h Header) String() (s string) {
	for i, v := range h {
		if i > 0 {
			s += "\n"
		}
		s += v.String()
	}
	return
}

func (h Header) JSON() string {
	s, _ := h.marshalJSON()
	return string(s)
}

func (h Header) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

func (h *Header) UnmarshalText(data []byte) error {
	v, err := ParseHeader(string(data))
	if v != nil {
		*h = v
	}
	return err
}

func (h Header) marshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString("{")
	for i, v := range h {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(toJSON(v.Key))
		buf.WriteByte(':')
		buf.WriteString(jsonEncode(v.Value))
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

//-------------------------------------------
func (h Header) indexOf(key string) int {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Key == key {
			return i
		}
	}
	return -1
}

//func (h Header) ContentMerkleRoot() []byte {
//	return h.GetBytes(HeaderMerkle)
//}

func (h Header) Has(key string) bool {
	return h.indexOf(key) >= 0
}

func (h Header) Get(key string) string {
	return string(h.GetBytes(key))
}

func (h Header) GetBytes(key string) []byte {
	if i := h.indexOf(key); i >= 0 {
		return h[i].Value
	}
	return nil
}

func (h Header) GetInt(key string) int64 {
	i, _ := strconv.ParseInt(h.Get(key), 10, 64)
	return i
}

func (h Header) GetTime(key string) time.Time {
	t, _ := time.Parse(time.RFC3339, h.Get(key))
	return t
}

func (h *Header) Set(key, value string) {
	h.SetBytes(key, []byte(value))
}

func (h *Header) SetBytes(key string, value []byte) {
	if i := h.indexOf(key); i >= 0 {
		(*h)[i].Value = value
	} else {
		*h = append(*h, KeyValue{key, value})
	}
}

func (h *Header) SetInt(key string, value int64) {
	h.Set(key, strconv.FormatInt(value, 10))
}

func (h *Header) SetTime(key string, value time.Time) {
	h.Set(key, value.Format(time.RFC3339))
}

func (h *Header) Add(key, value string) {
	h.AddBytes(key, []byte(value))
}

func (h *Header) AddBytes(key string, value []byte) {
	*h = append(*h, KeyValue{key, value})
}

func (h *Header) AddInt(key string, value int64) {
	h.Add(key, strconv.FormatInt(value, 10))
}

func (h *Header) AddTime(key string, value time.Time) {
	h.Add(key, value.Format(time.RFC3339))
}

func (h *Header) Exclude(key string) {
	for i := h.indexOf(key); i >= 0; i = h.indexOf(key) {
		c := *h
		copy(c[i:], c[i+1:])
		*h = c[:len(c)-1]
	}
}

func (h Header) Hash() []byte {
	n := len(h)
	if n == 0 {
		return nil
	}
	//switch h[n-1].Key { // last header
	//case HeaderSignature: // exclude Signature-Header
	//	return h[:n-1].Hash()
	//case HeaderMerkle:
	//	return hash256(h[:n-1].Hash(), h[n-1].Hash())
	//}
	if n == 1 {
		return h[0].Hash()
	}
	i := merkleMiddle(n)
	return hash256(h[:i].Hash(), h[i:].Hash())
}

func (h Header) Length() (n int) {
	for _, kv := range h {
		n += len(kv.Key) + len(kv.Value)
	}
	return
}

func (h Header) totalVolume() int64 {
	return int64(h.Length()) + h.Size()
}

//--------------------------------------
//        pre-defined params
//--------------------------------------

func (h Header) Path() string {
	return h.Get("Path")
}

func (h Header) IsDir() bool {
	return strings.HasSuffix(h.Path(), "/")
}

func (h Header) IsFile() bool {
	return !h.IsDir()
}

/*

Path: /dir/file
Ver: 45
Content-Size: 193858
Content-Merkle: base64,qwertyuiofghjklsdgjdkyguygguyguggusfjff

Path: /dir/file
Ver: 45
Volume: 193858
Merkle: base64,qwertyuiofghjklsdgjdkyguygguyguggusfjff

Path: /
Ver: 45
Tree-Volume: 193858
Tree-Merkle: base64,qwertyuiofghjklsdgjdkyguygguyguggusfjff

*/

func (h Header) Deleted() bool {
	return h.Has(HeaderDeleted)
}

// Protocol returns UFS-Protocol
func (h Header) Protocol() string {
	return h.Get("Protocol")
}

// Ver returns last file or dir-version. batch-version
func (h Header) Ver() int64 {
	return h.GetInt(HeaderVer)
}

func (h Header) PartSize() int64 {
	if i := h.GetInt("Part-Size"); i != 0 {
		return i
	}
	return DefaultPartSize
}

func (h Header) Updated() time.Time {
	return h.GetTime("Updated")
}

func (h Header) Created() time.Time {
	return h.GetTime("Created")
}

func (h Header) Size() int64 {
	return h.GetInt("Size")
}

func (h Header) Merkle() []byte {
	return h.GetBytes("Merkle")
}

func (h Header) PublicKey() PublicKey {
	return DecodePublicKey(h.Get(HeaderPublicKey))
}

func (h *Header) SetPublicKey(pub PublicKey) {
	//h.Exclude(HeaderPublicKey)
	h.Set(HeaderPublicKey, EncodePublicKey(pub))
}

func (h *Header) Sign(prv PrivateKey) {
	h.SetPublicKey(prv.Public().(PublicKey))

	h.Exclude(HeaderSignature)
	h.AddBytes(HeaderSignature, Sign(prv, h.Hash()))
}

func (h Header) Verify() bool {
	n := len(h)
	return n >= 2 &&
		h[n-1].Key == HeaderSignature && // last key is "Signature"
		Verify(h.PublicKey(), h[:n-1].Hash(), h[n-1].Value)
}

//--------------------------------------------------------

func ParseHeader(s string) (h Header, err error) {
	for _, s := range strings.Split(s, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			var kv KeyValue
			if i := strings.Index(s, ": "); i > 0 {
				if kv.Key, err = decodeHeaderKey(s[:i]); err != nil {
					return
				}
				if kv.Value, err = decodeHeaderValue(s[i+2:]); err != nil {
					return
				}
			} else {
				if kv.Key, err = decodeHeaderKey(s[:i]); err != nil {
					return
				}
			}
			h = append(h, kv)
		}
	}
	return
}

func sortHeaders(hh []Header) {
	sort.Slice(hh, func(i, j int) bool {
		return pathLess(hh[i].Path(), hh[j].Path())
	})
}

func traceHeaders(hh []Header) {
	for _, h := range hh {
		println("  - ", h.JSON())
	}
	println("")
}
