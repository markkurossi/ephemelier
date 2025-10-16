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
)

// FD defines a file descriptor.
type FD struct {
	refcount int
	Impl     FDImpl
}

// NewFD creates a new FD for the implementation.
func NewFD(impl FDImpl) *FD {
	return &FD{
		refcount: 1,
		Impl:     impl,
	}
}

// Copy creates a copy of the FD. The copy shares the underlying FD
// implementation i.e. this adds a reference for the FD instance and
// returns it.
func (fd *FD) Copy() *FD {
	if fd.refcount > 0 {
		fd.refcount++
	}
	return fd
}

// Close removes a reference from the FD. If this was the last
// reference, the underlying implementation is closed.
func (fd *FD) Close() int {
	if fd.refcount == 0 {
		return 0
	}
	fd.refcount--
	if fd.refcount > 0 {
		return 0
	}
	return fd.Impl.Close()
}

// Read reads data to the buffer b from the underlying FD
// implementation. It returns the number of bytes read or -Errno on
// error.
func (fd *FD) Read(b []byte) int {
	return fd.Impl.Read(b)
}

// Write writes data from the buffer b to the underlying FD
// implementation. It returns the number of bytes written or -Errno on
// error.
func (fd *FD) Write(b []byte) int {
	return fd.Impl.Write(b)
}

// FDImpl is the implementation of a file descriptor.
type FDImpl interface {
	Close() int
	Read(b []byte) int
	Write(b []byte) int
}

var (
	_ FDImpl = &FDFile{}
	_ FDImpl = &FDSocket{}
	_ FDImpl = &FDPort{}
	_ FDImpl = &FDDevNull{}
)

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
