package vfs

import (
	"bytes"
	"encoding/json"
	"github.com/denisskin/dweb/crypto"
	"mime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Header []HeaderField

type HeaderField struct {
	Name  string `json:"name"`  //
	Value []byte `json:"value"` //
}

const headerFieldNameCharset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."

const MaxHeaderLength = 10 * 1024 // 10 KiB

// predefined header-field-names
const (
	// root header fields
	headerProtocol       = "Protocol"         //
	headerPublicKey      = "Public-Key"       //
	headerSignature      = "Signature"        //
	headerTreeVolume     = "Tree-Volume"      // volume of full file tree
	headerTreeMerkleRoot = "Tree-Merkle-Root" // root merkle of full file tree

	// general
	headerVer     = "Ver"     // file or dir-version
	headerPath    = "Path"    // file or dir-path
	headerCreated = "Created" //
	headerUpdated = "Updated" //
	headerDeleted = "Deleted" //

	// files
	headerFileSize   = "Size"       // file size
	headerFileMerkle = "Merkle"     // file merkle-root := MerkleRoot(fileParts...)
	headerPieceSize  = "Piece-Size" // file piece size
)

func NewRootHeader(pub crypto.PublicKey) (h Header) {
	h.Add(headerProtocol, DefaultProtocol)
	h.Add(headerPath, "/")
	h.AddInt(headerVer, 0)
	h.AddInt(headerPieceSize, DefaultFilePieceSize)
	h.SetPublicKey(pub)
	return
}

func isValidHeaderKey(key string) bool {
	// todo: optimize, use charset-table as array  (see net/textproto/reader.go isTokenTable)
	return containsOnly(key, headerFieldNameCharset)
}

func encodeHeaderValue(v []byte) string {
	// todo: use binary encoding (not string)
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

func (v HeaderField) Hash() []byte {
	return crypto.MerkleRoot(
		crypto.Hash256([]byte(v.Name)),
		crypto.Hash256(v.Value),
	)
}

func (v HeaderField) String() string {
	return encodeHeaderValue([]byte(v.Name)) + ": " + encodeHeaderValue(v.Value)
}

func (v HeaderField) JSON() string {
	return "{" + toJSON(v.Name) + ":" + toJSON(v.Value) + "}"
}

func (v HeaderField) MarshalJSON() ([]byte, error) {
	return []byte(v.JSON()), nil
}

func (v *HeaderField) UnmarshalJSON(data []byte) (err error) {
	var vv map[string][]byte
	if err = json.Unmarshal(data, &vv); err == nil && vv != nil {
		for k, val := range vv {
			v.Name, v.Value = k, val
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
		buf.WriteString(toJSON(v.Name))
		buf.WriteByte(':')
		buf.WriteString(jsonEncode(v.Value))
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

//-------------------------------------------
func (h Header) indexOf(key string) int {
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].Name == key {
			return i
		}
	}
	return -1
}

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
		*h = append(*h, HeaderField{key, value})
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
	*h = append(*h, HeaderField{key, value})
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
	if n > 0 && h[n-1].Name == headerSignature { // exclude last header "Signature"
		n--
	}
	return crypto.MakeMerkleRoot(n, func(i int) []byte {
		return h[i].Hash()
	})
}

func (h Header) Length() (n int) {
	for _, kv := range h {
		n += len(kv.Name) + len(kv.Value)
	}
	return
}

func (h Header) totalVolume() int64 {
	return int64(h.Length()) + h.FileSize()
}

//--------------------------------------
//        pre-defined params
//--------------------------------------

func (h Header) Path() string {
	return h.Get(headerPath)
}

func (h Header) IsDir() bool {
	return strings.HasSuffix(h.Path(), "/")
}

func (h Header) IsFile() bool {
	return !h.IsDir()
}

func (h Header) Deleted() bool {
	return h.Has(headerDeleted)
}

// Ver returns last file or dir-version. batch-version
func (h Header) Ver() int64 {
	return h.GetInt(headerVer)
}

func (h Header) PieceSize() int64 {
	return h.GetInt(headerPieceSize)
}

func (h Header) Updated() time.Time {
	return h.GetTime(headerUpdated)
}

func (h Header) Created() time.Time {
	return h.GetTime(headerCreated)
}

func (h Header) FileSize() int64 {
	return h.GetInt(headerFileSize)
}

func (h Header) FileMerkle() []byte {
	return h.GetBytes(headerFileMerkle)
}

func (h Header) TreeMerkleRoot() []byte {
	return h.GetBytes(headerTreeMerkleRoot)
}

//--------- root-header crypto methods ----------

// Protocol returns VFS-Protocol
func (h Header) Protocol() string {
	return h.Get(headerProtocol)
}

func (h Header) PublicKey() crypto.PublicKey {
	return crypto.DecodePublicKey(h.Get(headerPublicKey))
}

func (h *Header) SetPublicKey(pub crypto.PublicKey) {
	//h.Exclude(HeaderPublicKey)
	h.Set(headerPublicKey, pub.Encode())
}

func (h *Header) Sign(prv crypto.PrivateKey) {
	h.SetPublicKey(prv.PublicKey())

	h.Exclude(headerSignature)
	h.AddBytes(headerSignature, prv.Sign(h.Hash()))
}

func (h Header) Verify() bool {
	n := len(h)
	return n >= 2 &&
		h[n-1].Name == headerSignature && // last key is "Signature"
		h.PublicKey().Verify(h[:n-1].Hash(), h[n-1].Value)
}

//--------------------------------------------------------

func ParseHeader(s string) (h Header, err error) {
	for _, s := range strings.Split(s, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			var kv HeaderField
			if i := strings.IndexByte(s, ':'); i >= 0 {
				if kv.Name, err = decodeHeaderKey(s[:i]); err != nil {
					return
				}
				if kv.Value, err = decodeHeaderValue(strings.TrimLeft(s[i+2:], " \t")); err != nil {
					return
				}
			} else {
				if kv.Name, err = decodeHeaderKey(s[:i]); err != nil {
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
