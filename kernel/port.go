//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/rand"
	"errors"
	"sync"
)

// Port implements IPC ports.
type Port struct {
	m       sync.Mutex
	key     []byte
	nonceHi uint32
	nonceLo uint64
	server  chan []byte
	client  chan []byte
}

// NewPort creates a new port for the role.
func NewPort(role Role) (*Port, error) {
	var key [KeySize]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}
	port := &Port{
		key: key[:],
	}
	if role == RoleGarbler {
		port.server = make(chan []byte)
		port.client = make(chan []byte)
	}
	return port, nil
}

// Nonce increments the port's nonce and stores the value into b.
func (p *Port) Nonce(b []byte) error {
	p.m.Lock()
	defer p.m.Unlock()

	p.nonceLo++
	if p.nonceLo == 0 {
		p.nonceHi++
		if p.nonceHi&0b10000000_00000000_00000000_00000000 != 0 {
			return errors.New("nonce overflow")
		}
	}

	bo.PutUint32(b[0:], p.nonceHi)
	bo.PutUint64(b[4:], p.nonceLo)

	return nil
}

// NewServerFD creates a server FD for the port.
func (p *Port) NewServerFD() *FD {
	return NewFD(&FDPort{
		port:   p,
		server: true,
		read:   p.server,
		write:  p.client,
	})
}

// NewClientFD creates a client FD for the port.
func (p *Port) NewClientFD() *FD {
	return NewFD(&FDPort{
		port:  p,
		read:  p.client,
		write: p.server,
	})
}

// FDPort implements port FDs.
type FDPort struct {
	port   *Port
	server bool
	closed bool
	peeked []byte
	read   chan []byte
	write  chan []byte
}

// Close implements FD.Close.
func (fd *FDPort) Close() int {
	if fd.closed {
		return int(-EBADF)
	}
	if fd.write != nil {
		close(fd.write)
	}
	fd.closed = true
	return 0
}

// Read implements FD.Read.
func (fd *FDPort) Read(b []byte) int {
	if fd.closed {
		return 0
	}
	if fd.read == nil {
		// Evaluator
		if len(b) < len(fd.port.key) {
			return int(-ERANGE)
		}
		return copy(b, fd.port.key)
	}

	var ok bool
	if fd.peeked == nil {
		fd.peeked, ok = <-fd.read
		if !ok {
			return 0
		}
	}
	msgSize := KeySize + len(fd.peeked)
	if msgSize > len(b) {
		return int(-ERANGE)
	}
	n := copy(b, fd.port.key)
	n += copy(b[KeySize:], fd.peeked)
	fd.peeked = nil
	return n
}

// Write implements FD.Write.
func (fd *FDPort) Write(b []byte) int {
	if fd.closed {
		return int(-EBADF)
	}
	n := len(b)
	if fd.write != nil {
		fd.write <- b
	}

	return n
}

// CreateMsg creates a message header for the port. The header is
// keyshare|nonce for RoleGarbler and keyshare for RoleEvaluator.
func (fd *FDPort) CreateMsg() []byte {
	l := KeySize
	if fd.write != nil {
		l += NonceSize
	}
	buf := make([]byte, l)
	n := copy(buf, fd.port.key[:])

	if fd.write != nil {
		fd.port.Nonce(buf[n:])
		if fd.server {
			buf[n] |= 0b10000000
		}
	}

	return buf
}
