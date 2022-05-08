package vfs

import (
	"errors"
	"io/fs"
	"strings"
	"time"
)

type VFS interface {
	PublicKey() PublicKey

	FileHeader(path string) (Header, error)
	FileMerkleProof(path string) (hash, proof []byte, err error)
	FileParts(path string) (hashes [][]byte, err error)
	FileContent(path string, offset int64, size int) ([]byte, error)

	//OpenFile(path string) (io.Read, error)

	ListDir(path string) ([]Header, error)

	GetBatch(ver int64) (*Batch, error)
	MakeBatch(prv PrivateKey, src fs.FS, ts time.Time) (*Batch, error)
	PutBatch(*Batch) error
}

const (
	DefaultProtocol = "0.1"
	DefaultPartSize = 16 << 20

	PathMaxLength        = 255
	PathNameMaxLength    = 50
	PathMaxLevels        = 6
	PathMaxDirFilesCount = 1024

	pathNameChars = ".-_~@0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrTooManyFiles = errors.New("too many files")
)

func IsValidPath(path string) bool {
	if path == "/" {
		return true
	}
	n := len(path)
	if n == 0 || path[0] != '/' || n > PathMaxLength {
		return false
	}
	path = path[1:] // trim prefix '/'
	path = strings.TrimSuffix(path, "/")
	for i, name := range strings.Split(path, "/") { // todo: optimize
		if i >= PathMaxLevels || !isValidPathName(name) {
			return false
		}
	}
	return true
}

func isValidPathName(name string) bool {
	return name != "" && // len>0
		name[0] != '.' && // not started from dot
		len(name) <= PathNameMaxLength && //
		containsOnly(name, pathNameChars) //
}

func dirname(path string) string {
	if n := len(path); n > 0 {
		if path[n-1] == '/' { // is dir
			path = path[:n-1]
		}
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			return path[:i+1]
		}
	}
	return ""
}
