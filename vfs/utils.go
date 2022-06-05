package vfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
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

func containsOnly(s, chars string) bool {
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
