package vfs

import (
	"bytes"
	"errors"
	"io"
	"strings"
)

// VFS is Virtual File System
type VFS interface {

	// FileHeader returns Header of file or directory
	FileHeader(path string) (Header, error)

	// FileMerkleProof returns hash and merkle-proof for file or dir-header
	FileMerkleProof(path string) (hash, proof []byte, err error)

	// FileParts returns hashes of file-parts
	FileParts(path string) (hashes [][]byte, err error)

	// OpenAt opens file as descriptor
	OpenAt(path string, offset int64) (io.ReadCloser, error)

	// ReadDir returns headers of directory files
	ReadDir(path string) ([]Header, error)

	// GetCommit makes commit starting from the given version
	GetCommit(ver int64) (*Commit, error)

	Get(request string) (*Commit, error)

	// Commit applies a commit
	Commit(*Commit) error
}

const (
	DefaultProtocol     = "0.1"
	DefaultFilePartSize = 1 << 20 // (1 MiB) – default file part size

	MaxPathLength        = 255
	MaxPathNameLength    = 50
	MaxPathLevels        = 6
	MaxPathDirFilesCount = 1024

	pathNameChars = ".-_~@0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrTooManyFiles = errors.New("too many files")

	errInvalidHeader = errors.New("invalid header")
	errInvalidPath   = errors.New("invalid header Path")
)

// IsValidPath says the path is valid
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

// VersionIsGreater checks that the version of header A is higher than the version of header B
func VersionIsGreater(a, b Header) bool {
	if a.Ver() != b.Ver() {
		return a.Ver() > b.Ver()
	}
	//if t1, t2 := a.Updated(), b.Updated(); t1 != t2 {
	//	return t1.Before(t2)
	//}
	return bytes.Compare(a.Hash(), b.Hash()) > 0
}
