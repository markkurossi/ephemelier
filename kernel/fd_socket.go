//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"errors"
	"io"
	"net"
)

// FDSocket implements socket FDs.
type FDSocket struct {
	conn net.Conn
}

// NewSocketFD creates a new socket FD.
func NewSocketFD(conn net.Conn) *FD {
	return NewFD(&FDSocket{
		conn: conn,
	})
}

// Close implements FD.Close.
func (fd *FDSocket) Close() int {
	err := fd.conn.Close()
	return mapError(err)
}

// Close implements FD.Read.
func (fd *FDSocket) Read(b []byte) int {
	n, err := fd.conn.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0
		}
		return mapError(err)
	}
	return n
}

// Close implements FD.Write.
func (fd *FDSocket) Write(b []byte) int {
	n, err := fd.conn.Write(b)
	if err != nil {
		return mapError(err)
	}
	return n
}
