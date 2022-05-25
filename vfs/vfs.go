package vfs

import (
	"bytes"
	"errors"
	"github.com/denisskin/dweb/crypto"
	"io"
	"io/fs"
	"strings"
	"time"
)

type VFS interface {
	PublicKey() crypto.PublicKey

	FileHeader(path string) (Header, error)
	FileMerkleProof(path string) (hash, proof []byte, err error)
	FileParts(path string) (hashes [][]byte, err error)
	Open(path string) (File, error)

	ReadDir(path string) ([]Header, error)

	GetBatch(ver int64) (*Batch, error)
	MakeBatch(prv crypto.PrivateKey, src fs.FS, ts time.Time) (*Batch, error)
	PutBatch(*Batch) error
}

type File interface {
	io.Reader
	io.Seeker
	io.Closer
}

const (
	DefaultProtocol      = "0.1"
	DefaultFilePieceSize = 1 << 20 // (1 MiB) – default file piece size

	MaxPathLength        = 255
	MaxPathNameLength    = 50
	MaxPathLevels        = 6
	MaxPathDirFilesCount = 1024

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
	if n == 0 || path[0] != '/' || n > MaxPathLength {
		return false
	}
	path = path[1:] // trim prefix '/'
	path = strings.TrimSuffix(path, "/")
	for i, name := range strings.Split(path, "/") { // todo: optimize
		if i >= MaxPathLevels || !isValidPathName(name) {
			return false
		}
	}
	return true
}

func isValidPathName(name string) bool {
	return name != "" && // len>0
		name[0] != '.' && // not started from dot
		len(name) <= MaxPathNameLength && //
		containsOnly(name, pathNameChars) //
}

func pathLess(a, b string) bool {
	// TODO: optimize
	A := strings.Split(a, "/")
	B := strings.Split(b, "/")
	nB := len(B)
	for i, Ai := range A {
		if nB < i+1 {
			return false
		} else if Ai != B[i] {
			return Ai < B[i]
		}
	}
	return true
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
