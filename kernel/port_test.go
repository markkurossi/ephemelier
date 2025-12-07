//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"bytes"
	"testing"
)

func TestPortNonce(t *testing.T) {
	port, err := NewPort(RoleGarbler)
	if err != nil {
		t.Fatal(err)
	}

	var nonce [NonceSize]byte

	err = port.Nonce(nonce[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nonce[:], []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 1}) {
		t.Errorf("nonce 1: %x", nonce[:])
	}
	err = port.Nonce(nonce[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nonce[:], []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 2}) {
		t.Errorf("nonce 2: %x", nonce[:])
	}

	port.nonceLo = 0xffffffffffffffff

	err = port.Nonce(nonce[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nonce[:], []byte{
		0, 0, 0, 1,
		0, 0, 0, 0,
		0, 0, 0, 0}) {
		t.Errorf("nonce 3: %x", nonce[:])
	}

	port.nonceLo = 0xffffffffffffffff
	port.nonceHi = 0b01111111_11111111_11111111_11111111

	err = port.Nonce(nonce[:])
	if err == nil {
		t.Errorf("nonce overflow not detected")
	}
}

func TestPortGarbler(t *testing.T) {
	port, err := NewPort(RoleGarbler)
	if err != nil {
		t.Fatal(err)
	}
	fd := port.NewServerFD()
	portfd, ok := fd.Impl.(*FDPort)
	if !ok {
		t.Fatalf("NewServerFD returned %T", fd)
	}

	msg := portfd.CreateMsg()
	if len(msg) != KeySize+NonceSize {
		t.Errorf("invalid garbler msg: %x", msg)
	}
}

func TestPortEvaluator(t *testing.T) {
	port, err := NewPort(RoleEvaluator)
	if err != nil {
		t.Fatal(err)
	}
	fd := port.NewServerFD()
	portfd, ok := fd.Impl.(*FDPort)
	if !ok {
		t.Fatalf("NewServerFD returned %T", fd)
	}

	msg := portfd.CreateMsg()
	if len(msg) != KeySize {
		t.Errorf("invalid evaluator msg: %x: %v != %v", msg, len(msg), KeySize)
	}
}
