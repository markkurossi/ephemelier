//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

var bo = binary.BigEndian

type Connection struct {
	conn net.Conn
	rbuf []byte
}

func NewConnection(conn net.Conn) *Connection {
	return &Connection{
		conn: conn,
		rbuf: make([]byte, 65536),
	}
}

func (conn *Connection) ServerHandshake() error {
	var handshake []byte
	for {
		ct, data, err := conn.ReadRecord()
		if err != nil {
			return err
		}
		if ct != CTHandshake {
			return fmt.Errorf("unexpected record %v, expected %v",
				ct, CTHandshake)
		}
		handshake = data
		break
	}
	if len(handshake) < 4 {
		return fmt.Errorf("truncated handshake")
	}
	typeLen := bo.Uint32(handshake)
	ht := HandshakeType(typeLen >> 24)
	length := typeLen & 0xffffff
	if int(length+4) != len(handshake) {
		return fmt.Errorf("handshake length mismatch: got %v, expected %v",
			length+4, len(handshake))
	}
	if ht != HTClientHello {
		return fmt.Errorf("invalid handshake: got %v, expected %v",
			ht, HTClientHello)
	}

	var ch ClientHello
	consumed, err := UnmarshalFrom(handshake[4:], &ch)
	if err != nil {
		return err
	}
	if consumed != len(handshake)-4 {
		return fmt.Errorf("trailing data after client_hello: len=%v",
			len(handshake)-4-consumed)
	}
	fmt.Printf("client_hello:\n")
	fmt.Printf(" - random: %x\n", ch.Random)

	fmt.Printf(" - cipher_suites: {")
	var col int
	for _, suite := range ch.CipherSuites {
		name, ok := tls13CipherSuites[suite]
		if col%12 == 0 || ok {
			fmt.Printf("\n     ")
			col = 0
		} else {
			fmt.Printf(" ")
		}
		if ok {
			fmt.Printf("%v", name)
		} else {
			fmt.Printf("%04x", int(suite))
		}
		col++
	}
	if col > 0 {
		fmt.Println()
	}
	fmt.Printf("   }\n")

	fmt.Printf(" - extensions: {")
	col = 0
	for _, ext := range ch.Extensions {
		_, ok := tls13Extensions[ext.Type]
		if col%12 == 0 || ok {
			fmt.Printf("\n     ")
			col = 0
		} else {
			fmt.Printf(" ")
		}
		col++

		if ok {
			fmt.Printf("%v", ext)
			col = 12
		} else {
			fmt.Printf("%v", ext)
		}
	}
	if col > 0 {
		fmt.Println()
	}
	fmt.Printf("   }\n")

	return nil
}

func (conn *Connection) ReadRecord() (ContentType, []byte, error) {
	// Read record header.
	for i := 0; i < 5; {
		n, err := conn.conn.Read(conn.rbuf[i : 5-i])
		if err != nil {
			return CTInvalid, nil, err
		}
		i += n
	}
	fmt.Printf("Header:\n%s", hex.Dump(conn.rbuf[:5]))

	ct := ContentType(conn.rbuf[0])
	legacyVersion := ProtocolVersion(bo.Uint16(conn.rbuf[1:3]))
	length := int(bo.Uint16(conn.rbuf[3:5]))

	fmt.Printf(" - ContentType    : %v\n", ct)
	fmt.Printf(" - ProtocolVersion: %v\n", legacyVersion)
	fmt.Printf(" - length         : %v\n", length)

	for i := 0; i < length; {
		n, err := conn.conn.Read(conn.rbuf[i : length-i])
		if err != nil {
			return CTInvalid, nil, err
		}
		i += n
	}
	fmt.Printf("Data:\n%s", hex.Dump(conn.rbuf[:length]))
	fmt.Printf("%x\n", conn.rbuf[:length])

	return ct, conn.rbuf[:length], nil
}
