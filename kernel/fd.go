//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

// FD implements a file descriptor.
type FD interface {
	Close() int
	Read(b []byte) int
	Write(b []byte) int
}

var (
	_ FD = &FDFile{}
)
