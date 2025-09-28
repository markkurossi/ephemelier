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

// FD implements a file descriptor.
type FD interface {
	Close() int
	Read(b []byte) int
	Write(b []byte) int
}

var (
	_ FD = &FDFile{}
	_ FD = &FDSocket{}
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
