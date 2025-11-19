//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

// FDTLS implements TLS client and server FDs.
type FDTLS struct {
	conn *tls.Conn
	priv *ecdsa.PrivateKey
	cert *x509.Certificate
}

// NewTLSFD creates a new TLS FD. The arguments must be non-nil for
// garbler and nil for evaluator.
func NewTLSFD(conn *tls.Conn, priv *ecdsa.PrivateKey,
	cert *x509.Certificate) *FD {

	return NewFD(&FDTLS{
		conn: conn,
		priv: priv,
		cert: cert,
	})
}

// Close implements FD.Close.
func (fd *FDTLS) Close() int {
	if fd.conn == nil {
		return 0
	}
	return mapError(fd.conn.Close())
}

// Read implements FD.Read.
func (fd *FDTLS) Read(b []byte) int {
	if fd.conn == nil {
		return 0
	}
	n, err := fd.conn.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0
		}
		return mapError(err)
	}
	return n
}

// Write implements FD.Write.
func (fd *FDTLS) Write(b []byte) int {
	if fd.conn == nil {
		return len(b)
	}
	n, err := fd.conn.Write(b)
	if err != nil {
		return mapError(err)
	}
	return n
}
