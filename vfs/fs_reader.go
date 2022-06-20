package vfs

import (
	"io"
	"io/fs"
)

type filesReader struct {
	fs interface{}
	pp []string
	r  io.ReadCloser
}

func newFilesReader(fs interface{}) *filesReader {
	return &filesReader{fs: fs}
}

func (f *filesReader) addFile(path string) {
	f.pp = append(f.pp, path)
}

func (f *filesReader) open(path string) (io.ReadCloser, error) {
	switch f := f.fs.(type) {
	case fs.FS:
		return f.Open(path)

	case interface {
		Open(key string) (io.ReadSeekCloser, error)
	}:
		return f.Open(path)

	case interface {
		Open(key string) (io.ReadCloser, error)
	}:
		return f.Open(path)
	}
	panic("unknown type")
}

func (f *filesReader) Read(buf []byte) (n int, err error) {
	for len(buf) > 0 && len(f.pp) > 0 {
		if f.r == nil {
			if f.r, err = f.open(f.pp[0]); err != nil {
				return n, err
			}
			f.pp = f.pp[1:]
		}
		var m int
		if m, err = f.r.Read(buf); err == io.EOF {
			f.r, err = nil, f.r.Close()
		}
		n += m
		if err != nil {
			return
		}
		buf = buf[m:]
	}
	if len(buf) > 0 {
		err = io.EOF
	}
	return
}

func (f *filesReader) Close() error {
	if r := f.r; r != nil {
		f.r = nil
		return r.Close()
	}
	return nil
}
