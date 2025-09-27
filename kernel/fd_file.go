//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// FDFile implements file FDs.
type FDFile struct {
	f *os.File
}

// NewFileFD creates a new file FD.
func NewFileFD(f *os.File) *FDFile {
	return &FDFile{
		f: f,
	}
}

// Close implements FD.Close.
func (fd *FDFile) Close() int {
	err := fd.f.Close()
	return mapError(err)
}

// Close implements FD.Read.
func (fd *FDFile) Read(b []byte) int {
	n, err := fd.f.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0
		}
		return mapError(err)
	}
	return n
}

// Close implements FD.Write.
func (fd *FDFile) Write(b []byte) int {
	n, err := fd.f.Write(b)
	if err != nil {
		return mapError(err)
	}
	return n
}

func mapError(err error) int {
	if err == nil {
		return 0
	}
	var perr *fs.PathError
	if errors.As(err, &perr) || errors.Is(err, io.EOF) {
		return int(-EBADF)
	}
	return int(-EINVAL)
}
