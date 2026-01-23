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
	"strings"
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
func (proc *Process) MakePath(path string) string {
	if path[0] != '/' {
		path = filepath.Join(proc.cwd, path)
	}
	path = filepath.Clean(path)
	return filepath.Join(proc.kern.params.Filesystem, proc.root, path)
}

// Chroot changes the process' root directory.
func (proc *Process) Chroot(path string) error {
	path = proc.MakePath(path)

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return Errno(ENOTDIR)
	}
	proc.root = path[len(proc.kern.params.Filesystem):]
	if strings.HasPrefix(path, proc.cwd) {
		proc.cwd = proc.cwd[len(path):]
	} else {
		proc.cwd = "/"
	}
	return nil
}

// MakeFileInfo encodes info into []byte buffer.
func MakeFileInfo(info os.FileInfo) []byte {
	buf := make([]byte, 16)

	bo.PutUint64(buf[0:], uint64(info.Size()))
	bo.PutUint64(buf[8:], uint64(info.ModTime().UnixMilli()))

	return buf
}
