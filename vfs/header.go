package vfs

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/denisskin/dweb/crypto"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Header []HeaderField

type HeaderField struct {
	Name  string //
	Value []byte //
}

const MaxHeaderLength = 10 * 1024 // 10 KiB

const (
	headerFieldNameCharset  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_."
	headerBinaryValuePrefix = "base64,"
	headerTextValueChars    = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.,:;+=?~!@#$%^&*()<>[]{}/| "
)

var errInvalidJSON = errors.New("invalid JSON")

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
	headerFileSize   = "Size"      // file size
	headerFileMerkle = "Merkle"    // file merkle-root := MerkleRoot(fileParts...)
	headerPartSize   = "Part-Size" // file part size
)

func NewRootHeader(pub crypto.PublicKey) (h Header) {
	h.Add(headerProtocol, DefaultProtocol)
	h.Add(headerPath, "/")
	h.AddInt(headerVer, 0)
	h.AddInt(headerPartSize, DefaultFilePartSize)
	h.SetPublicKey(pub)
	return
}

func ValidateHeader(h Header) error {
	if h.Length() > MaxHeaderLength {
		return errInvalidHeaderLength
	}
	for _, kv := range h {
		if !isValidHeaderKey(kv.Name) {
			return errInvalidHeaderName
		}
	}
	if !IsValidPath(h.Path()) {
		return errInvalidPath
	}
	return nil
}

func isValidHeaderKey(key string) bool {
	// todo: optimize, use charset-table as array  (see net/textproto/reader.go isTokenTable)
	return containsOnly(key, headerFieldNameCharset)
}

func (v HeaderField) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString("{")
	buf.Write(marshalKey(v.Name))
	buf.WriteByte(':')
	buf.Write(marshalValue(v.Value))
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (v *HeaderField) UnmarshalJSON(data []byte) (err error) {
	var vv map[string]string
	if err = json.Unmarshal(data, &vv); err == nil && vv != nil {
		for k, val := range vv {
			v.Name = k
			v.Value, err = unmarshalValue(val)
			break
		}
	}
	return
}

//-------------------------------------------------------------

func (h Header) Copy() Header {
	h1 := make(Header, len(h))
	copy(h1, h)
	return h1
}

func (h Header) String() string {
	s, _ := h.MarshalJSON()
	return string(s)
}

func (h Header) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString("{")
	for i, v := range h {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(marshalKey(v.Name))
		buf.WriteByte(':')
		buf.Write(marshalValue(v.Value))
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (h *Header) UnmarshalJSON(data []byte) (err error) {
	n := len(data)
	if n < 2 || data[0] != '{' || data[n-1] != '}' {
		return errInvalidJSON
	}
	// replace object to array:  {"key":"value",...} -> ["key","value",...]
	data = bytes.ReplaceAll(data, []byte(`":"`), []byte(`","`))
	data[0], data[n-1] = '[', ']'
	var ss []string
	if err = json.Unmarshal(data, &ss); err != nil {
		return
	}
	*h = (*h)[:0]
	var kv HeaderField
	for i, v := range ss {
		if i%2 == 0 { // key
			kv.Name = v
		} else { // value
			if kv.Value, err = unmarshalValue(v); err != nil {
				return err
			}
			*h = append(*h, kv)
		}
	}
	return
}

var (
	txtValChars = []byte(headerTextValueChars)
	binValPfx   = []byte(headerBinaryValuePrefix)
)

func marshalKey(v string) []byte {
	// todo: optimize it; use fast string marshaling
	b, _ := json.Marshal(v)
	return b
}

func marshalValue(v []byte) []byte {
	buf := bytes.NewBufferString(`"`)
	if bContainOnly(v, txtValChars) && !bytes.HasPrefix(v, binValPfx) {
		buf.Write(v)
	} else {
		buf.Write(binValPfx)
		buf.WriteString(base64.RawStdEncoding.EncodeToString(v))
	}
	buf.WriteByte('"')
	return buf.Bytes()
}

func unmarshalValue(v string) ([]byte, error) {
	if strings.HasPrefix(v, headerBinaryValuePrefix) {
		return base64.RawStdEncoding.DecodeString(strings.TrimPrefix(v, headerBinaryValuePrefix))
	}
	return []byte(v), nil
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

func (h *Header) Delete(key string) {
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
	hsh := crypto.NewHash()
	buf := make([]byte, 4)
	for _, kv := range h[:n-1] {
		// write <len><Name>
		binary.BigEndian.PutUint32(buf, uint32(len(kv.Name)))
		hsh.Write(buf)
		hsh.Write([]byte(kv.Name))

		// write <len><Value>
		binary.BigEndian.PutUint32(buf, uint32(len(kv.Value)))
		hsh.Write(buf)
		hsh.Write(kv.Value)
	}
	return hsh.Sum(nil)
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

func (h Header) PartSize() int64 {
	return h.GetInt(headerPartSize)
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
	//h.Delete(HeaderPublicKey)
	h.Set(headerPublicKey, pub.Encode())
}

func (h *Header) Sign(prv crypto.PrivateKey) {
	h.SetPublicKey(prv.PublicKey())

	h.Delete(headerSignature)
	h.AddBytes(headerSignature, prv.Sign(h.Hash()))
}

func (h Header) Verify() bool {
	n := len(h)
	return n >= 2 &&
		h[n-1].Name == headerSignature && // last key is "Signature"
		h.PublicKey().Verify(h[:n-1].Hash(), h[n-1].Value)
}

//--------------------------------------------------------

func sortHeaders(hh []Header) {
	sort.Slice(hh, func(i, j int) bool {
		return pathLess(hh[i].Path(), hh[j].Path())
	})
}

func traceHeaders(hh []Header) {
	for _, h := range hh {
		println("  - ", h.String())
	}
	println("")
}
