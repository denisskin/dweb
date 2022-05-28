package vfs

import (
	"errors"
	"github.com/denisskin/dweb/crypto"
	"strings"
)

type fsNode struct {
	Header   Header
	path     string
	children []*fsNode
}

var (
	errSeveralNodes       = errors.New("several nodes with the same path")
	errParentDirNotFound  = errors.New("parent dir not found")
	errParentDirIsDeleted = errors.New("parent dir is deleted")
)

func indexTree(hh []Header) (nodes map[string]*fsNode, err error) {
	nodes = make(map[string]*fsNode, len(hh))
	for _, h := range hh {
		path := h.Path()
		if nodes[path] != nil { // can`t repeat
			return nil, errSeveralNodes
		}
		nd := &fsNode{Header: h, path: path}
		nodes[path] = nd
		if path == "/" {
			continue
		}
		if p := nodes[dirname(path)]; p == nil { // find parent node
			return nil, errParentDirNotFound
		} else if p.Header.Deleted() {
			return nil, errParentDirIsDeleted
		} else {
			p.children = append(p.children, nd)
		}
	}
	return
}

//func (nd *fsNode) setChild(ch *fsNode) {
//	if nd.Header.Deleted() {
//		panic(errParentDirIsDeleted)
//	}
//	// todo: ? bin-search i := sort.Search(len(nd.children), func(i int) bool { return nd.children[i].path <=ch.path  })
//	for i, c := range nd.children {
//		if c.path == ch.path {
//			nd.children[i] = ch
//			return
//		}
//	}
//	nd.children = append(nd.children, ch)
//}

//func (nd *fsNode) clone() *fsNode {
//	cc := make([]*fsNode, len(nd.children))
//	copy(cc, nd.children)
//	return &fsNode{
//		Header:   nd.Header.Copy(),
//		path:     nd.path,
//		children: cc,
//	}
//}

func (nd *fsNode) childHeaders() []Header {
	hh := make([]Header, len(nd.children))
	for i, c := range nd.children {
		hh[i] = c.Header
	}
	return hh
}

func (nd *fsNode) walk(fn func(nd *fsNode) bool) {
	if fn(nd) {
		for _, c := range nd.children {
			c.walk(fn)
		}
	}
}

func (nd *fsNode) deleted() bool {
	return nd != nil && nd.Header.Deleted()
}

func (nd *fsNode) isDir() bool {
	return strings.HasSuffix(nd.path, "/")
}

func (nd *fsNode) hasFile(path string) bool {
	return nd.path == path || nd.isDir() && strings.HasPrefix(path, nd.path)
}

func (nd *fsNode) merkleRoot() []byte {
	if len(nd.children) == 0 {
		return nd.Header.Hash()
	}
	return crypto.MerkleRoot(nd.Header.Hash(), nd.childrenMerkleRoot())
}

func (nd *fsNode) merkleProof(path string) []byte {
	if nd.path == path {
		if len(nd.children) == 0 { // is file or empty dir
			return nd.Header.Hash()
		}
		return crypto.MakeMerkleProof([][]byte{ // is dir
			nd.Header.Hash(),
			nd.childrenMerkleRoot(),
		}, 0)
	}
	return crypto.MerkleProofAppend(
		nd.childrenMerkleProof(path),
		crypto.OpLHash,
		nd.Header.Hash(),
	)
}

func (nd *fsNode) totalVolume() (n int64) {
	if nd.path != "/" { // exclude root
		n += nd.Header.totalVolume()
	}
	for _, c := range nd.children {
		n += c.totalVolume()
	}
	return n
}

func (nd *fsNode) childrenMerkleRoot() []byte {
	return crypto.MakeMerkleRoot(len(nd.children), func(i int) []byte {
		return nd.children[i].merkleRoot()
	})
}

func (nd *fsNode) childrenMerkleProof(path string) []byte {
	var hashes [][]byte
	var iHash int
	for i, sub := range nd.children {
		if sub.hasFile(path) {
			iHash = i
			hashes = append(hashes, sub.merkleProof(path))
		} else {
			hashes = append(hashes, sub.merkleRoot())
		}
	}
	return crypto.MakeMerkleProof(hashes, iHash)
}
