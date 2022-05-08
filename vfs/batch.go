package vfs

import "io"

type Batch struct {
	Headers []Header
	Body    io.Reader
}

func (b *Batch) Root() Header {
	return b.Headers[0]
}

func (b *Batch) BodySize() (n int64) {
	for _, h := range b.Headers {
		n += h.FileSize()
	}
	return
}

func (b *Batch) Sign(prv PrivateKey) {
	b.Headers[0].Sign(prv)
}

func (b *Batch) Trace() {
	traceHeaders(b.Headers)
}
