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
	role    Role
	server  chan msg
	client  chan msg
}

type msg struct {
	data []byte
	fd   *FD
}

// NewPort creates a new port for the role.
func NewPort(role Role) (*Port, error) {
	var key [KeySize]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}
	port := &Port{
		key:  key[:],
		role: role,
	}
	port.server = make(chan msg)
	port.client = make(chan msg)

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
	read   chan msg
	write  chan msg
}

// Close implements FD.Close.
func (fd *FDPort) Close() int {
	if fd.write == nil {
		return int(-EBADF)
	}
	close(fd.write)
	fd.write = nil
	return 0
}

// Read implements FD.Read.
func (fd *FDPort) Read(b []byte) int {
	if fd.read == nil {
		return 0
	}

	msg, ok := <-fd.read
	if !ok {
		return 0
	}
	if msg.fd != nil {
		msg.fd.Close()
		return int(-ENOMSG)
	}
	msgSize := KeySize + len(msg.data)
	if msgSize > len(b) {
		return int(-ERANGE)
	}
	n := copy(b, fd.port.key)
	n += copy(b[KeySize:], msg.data)

	return n
}

// Write implements FD.Write.
func (fd *FDPort) Write(b []byte) int {
	if fd.write == nil {
		return int(-EBADF)
	}
	n := len(b)
	if fd.port.role == RoleEvaluator {
		b = nil
	}
	fd.write <- msg{
		data: b,
	}

	return n
}

// RecvFD receives a file descriptor from the port's sender.
func (fd *FDPort) RecvFD() (*FD, int) {
	if fd.read == nil {
		return nil, int(-EBADF)
	}

	msg, ok := <-fd.read
	if !ok {
		return nil, int(-EBADF)
	}
	if msg.fd == nil {
		return nil, int(-ENOMSG)
	}

	return msg.fd, 0
}

// SendFD sends the file descriptor to port's receiver.
func (fd *FDPort) SendFD(v *FD) int {
	if fd.write == nil {
		return int(-EBADF)
	}
	fd.write <- msg{
		fd: v,
	}
	return 0
}

// CreateMsg creates a message header for the port. The header is
// keyshare|nonce for RoleGarbler and keyshare for RoleEvaluator.
func (fd *FDPort) CreateMsg() []byte {
	l := KeySize
	if fd.port.role == RoleGarbler {
		l += NonceSize
	}
	buf := make([]byte, l)
	n := copy(buf, fd.port.key[:])

	if fd.port.role == RoleGarbler {
		fd.port.Nonce(buf[n:])
		if fd.server {
			buf[n] |= 0b10000000
		}
	}

	return buf
}
