//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// FDFile implements file FDs.
type FDFile struct {
	f *os.File
}

// NewFileFD creates a new file FD.
func NewFileFD(f *os.File) *FD {
	return NewFD(&FDFile{
		f: f,
	})
}

// Close implements FD.Close.
func (fd *FDFile) Close() int {
	err := fd.f.Close()
	return int(mapError(err))
}

// Read implements FD.Read.
func (fd *FDFile) Read(b []byte) int {
	n, err := fd.f.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0
		}
		return int(mapError(err))
	}
	return n
}

// Write implements FD.Write.
func (fd *FDFile) Write(b []byte) int {
	n, err := fd.f.Write(b)
	if err != nil {
		return int(mapError(err))
	}
	return n
}

// MakePath creates a cleaned path from the path argument and the
// system state cwd, chroot, and root.
func MakePath(path, cwd, chroot, root string) string {
	if path[0] != '/' {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	return filepath.Join(root, chroot, path)
}

// MakeFileInfo encodes info into []byte buffer.
func MakeFileInfo(info os.FileInfo) []byte {
	buf := make([]byte, 16)

	bo.PutUint64(buf[0:], uint64(info.Size()))
	bo.PutUint64(buf[8:], uint64(info.ModTime().UnixMilli()))

	return buf
}
