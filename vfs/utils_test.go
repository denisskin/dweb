package vfs

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_dirname(t *testing.T) {
	assert.Equal(t, "", dirname("/"))
	assert.Equal(t, "/", dirname("/a.txt"))
	assert.Equal(t, "/", dirname("/aa/"))
	assert.Equal(t, "/aa/", dirname("/aa/bb"))
	assert.Equal(t, "/aa/bb/", dirname("/aa/bb/cc.txt"))
}

func Test_IsValidPath(t *testing.T) {
	assert.True(t, IsValidPath("/"))
	assert.True(t, IsValidPath("/"))
	assert.True(t, IsValidPath("/aaa/123_456-7890/Abc01.txt"))
	assert.True(t, IsValidPath("/~/@/-/a../_/Abc01.txt"))
	assert.True(t, IsValidPath("/aaa/111..-0/Abc01.txt"))
	assert.True(t, IsValidPath("/1/2/3/4/5/Abc01.txt"))
	assert.True(t, IsValidPath("/aaa/123456789-123456789-123456789-123456789-123456789-/Abc01.txt"))
	assert.True(t, IsValidPath(""+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/1234")) // path-length == 255

	assert.False(t, IsValidPath("/aaa//Abc01.txt"))
	assert.False(t, IsValidPath("/aaa/.111-0/Abc01.txt"))
	assert.False(t, IsValidPath("/aaa/./Abc01.txt"))
	assert.False(t, IsValidPath("/aaa/../Abc01.txt"))
	assert.False(t, IsValidPath("/aaa/.Abc01.txt"))
	assert.False(t, IsValidPath("/aaa/.../Abc01.txt"))
	assert.False(t, IsValidPath("/1/2/3/4/5/A/bc01.txt"))
	assert.False(t, IsValidPath("/aaa/123456789-123456789-123456789-123456789-123456789-1/Abc01.txt"))
	assert.False(t, IsValidPath(""+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/123456789-123456789-123456789-123456789-123456789"+
		"/12345")) // path-length == 256
}
