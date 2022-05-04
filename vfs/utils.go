package vfs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var testMode = len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-test.")

func assertNoErr(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func assertBool(f bool, err string) {
	if !f {
		assertNoErr(errors.New(err))
	}
}

func recoverErr(err *error) {
	//if testMode {
	//	return
	//}
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

//func hex8(h []byte) string {
//	if len(h) > 4 {
//		h = h[:4]
//	}
//	return hex.EncodeToString(h)
//}
//
//func hexDecode(s string) []byte {
//	b, _ := hex.DecodeString(s)
//	return b
//}

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}

var (
	_b2jChars = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ,.:;_-+=?~!@#$%^&*()<>[]{}/| ")
	_b2jPfx   = []byte("base64,")
)

func jsonEncode(v []byte) string {
	buf := bytes.NewBufferString(`"`)
	if bContainOnly(v, _b2jChars) && !bytes.HasPrefix(v, _b2jPfx) {
		buf.Write(v)
	} else {
		buf.Write(_b2jPfx)
		buf.WriteString(base64.RawStdEncoding.EncodeToString(v))
	}
	buf.WriteByte('"')
	return buf.String()
}

//func jsonDecode(v string) (data []byte, err error) {
//	//json.Unmarshal()
//	return
//}

func containOnly(s, chars string) bool {
	for _, c := range s {
		if strings.IndexRune(chars, c) == -1 {
			return false
		}
	}
	return true
}

func bContainOnly(s, chars []byte) bool {
	for _, c := range s {
		if bytes.IndexByte(chars, c) == -1 {
			return false
		}
	}
	return true
}

func toJSON(v interface{}) string {
	b, err := json.Marshal(v)
	assertNoErr(err)
	return string(b)
}

func toIndentJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	assertNoErr(err)
	return string(b)
}

func trace(title string, v interface{}) {
	if !testMode {
		return
	}
	println(title)
	if v, ok := v.(interface{ Trace() }); ok {
		v.Trace()
		return
	}
	println("====== TRACE: ", toIndentJSON(v))
}
