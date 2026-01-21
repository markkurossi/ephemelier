//
// Copyright (c) 2025-2026 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

// FDTLS implements TLS client and server FDs.
type FDTLS struct {
	conn          *tls.Conn
	key           *Key
	handshakeDone bool
}

// NewTLSFD creates a new TLS FD. The arguments must be non-nil for
// garbler and nil for evaluator.
func NewTLSFD(conn *tls.Conn, key *Key) *FD {
	return NewFD(&FDTLS{
		conn: conn,
		key:  key,
	})
}

// Close implements FD.Close.
func (fd *FDTLS) Close() int {
	if fd.conn == nil {
		return 0
	}
	return int(mapError(fd.conn.Close()))
}

// Read implements FD.Read.
func (fd *FDTLS) Read(b []byte) int {
	if fd.conn == nil {
		return 0
	}
	ct, data, err := fd.conn.ReadRecord()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0
		}
		return int(mapError(err))
	}
	need := len(data)
	if !fd.handshakeDone {
		need += sha256.Size
	}

	if need > len(b) {
		fmt.Printf("<< %s[%d/%d/%d]\n", ct, len(data), need, len(b))
		return -int(ERANGE)
	}
	var n int
	if !fd.handshakeDone {
		n = copy(b, fd.conn.Transcript())
	}
	n += copy(b[n:], data)

	return n
}

// Write implements FD.Write.
func (fd *FDTLS) Write(b []byte) int {
	if fd.conn == nil {
		return len(b)
	}
	err := fd.conn.WriteRecord(tls.CTApplicationData, b)
	if err != nil {
		return int(mapError(err))
	}
	return len(b)
}
