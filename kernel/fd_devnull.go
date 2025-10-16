//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

// FDDevNull implements null FDs.
type FDDevNull struct {
}

// NewDevNullFD creates a null FD.
func NewDevNullFD() *FD {
	return NewFD(&FDDevNull{})
}

// Close implements FD.Close.
func (fd *FDDevNull) Close() int {
	return 0
}

// Read implements FD.Read.
func (fd *FDDevNull) Read(b []byte) int {
	return 0
}

// Write implements FD.Write.
func (fd *FDDevNull) Write(b []byte) int {
	return len(b)
}
