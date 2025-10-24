//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// ParseNetAddress parses the network address buffer and returns its
// network and address parts.
func ParseNetAddress(buf []byte) (string, string, Errno) {
	idx := bytes.IndexByte(buf, ':')
	if idx <= 0 {
		return "", "", EINVAL
	}
	network := string(buf[:idx])
	address := string(buf[idx+1:])

	_, ok := knownNetworks[network]
	if !ok {
		return "", "", EPROTONOSUPPORT
	}

	return network, address, 0
}

var knownNetworks = map[string]bool{
	"tcp":        true,
	"tcp4":       true,
	"tcp6":       true,
	"udp":        true,
	"udp4":       true,
	"udp6":       true,
	"ip":         true,
	"ip4":        true,
	"ip6":        true,
	"unix":       true,
	"unixgram":   true,
	"unixpacket": true,
}

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

// Read implements FD.Read.
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

// Write implements FD.Write.
func (fd *FDSocket) Write(b []byte) int {
	n, err := fd.conn.Write(b)
	if err != nil {
		return mapError(err)
	}
	return n
}

// FDListener implements listener FDs.
type FDListener struct {
	listener net.Listener
}

// NewListenerFD creates a new listener FD.
func NewListenerFD(listener net.Listener) *FD {
	return NewFD(&FDListener{
		listener: listener,
	})
}

// Close implements FD.Close.
func (fd *FDListener) Close() int {
	err := fd.listener.Close()
	return mapError(err)
}

// Read implements FD.Read.
func (fd *FDListener) Read(b []byte) int {
	return int(-EINVAL)
}

// Write implements FD.Write.
func (fd *FDListener) Write(b []byte) int {
	return int(-EINVAL)
}
