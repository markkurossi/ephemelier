//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
)

var (
	bo = binary.BigEndian

	supportedVersions = map[ProtocolVersion]bool{
		VersionTLS13: true,
	}
	supportedCipherSuites = map[CipherSuite]bool{
		CipherTLSAes128GcmSha256: true,
	}
	supportedGroups = map[NamedGroup]bool{
		GroupSecp256r1: true,
		GroupX25519:    false,
	}
	supportedSignatureSchemes = map[SignatureScheme]bool{
		SigSchemeEcdsaSecp256r1Sha256: true,
	}
)

// Connection implements a TLS connection.
type Connection struct {
	conn net.Conn
	rbuf []byte
}

// NewConnection creates a new TLS connection for the argument conn.
func NewConnection(conn net.Conn) *Connection {
	return &Connection{
		conn: conn,
		rbuf: make([]byte, 65536),
	}
}

// Debugf prints debug output for the connection.
func (conn *Connection) Debugf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
}

// ServerHandshake runs the server handshake protocol.
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

	var versions []ProtocolVersion
	var cipherSuites []CipherSuite
	var groups []NamedGroup
	var signatureSchemes []SignatureScheme
	var clientKEX *KeyShareEntry

	conn.Debugf("client_hello:\n")
	conn.Debugf(" - random: %x\n", ch.Random)

	conn.Debugf(" - cipher_suites: {")
	var col int
	for _, suite := range ch.CipherSuites {
		if supportedCipherSuites[suite] {
			cipherSuites = append(cipherSuites, suite)
		}

		name, ok := tls13CipherSuites[suite]
		if col%12 == 0 || ok {
			conn.Debugf("\n     ")
			col = 0
		} else {
			conn.Debugf(" ")
		}
		if ok {
			conn.Debugf("%v", name)
		} else {
			conn.Debugf("%04x", int(suite))
		}
		col++
	}
	if col > 0 {
		fmt.Println()
	}
	conn.Debugf("   }\n")

	conn.Debugf(" - extensions: {")
	col = 0
	for _, ext := range ch.Extensions {
		switch ext.Type {
		case ETSupportedGroups:
			arr, err := ext.Uint16List(2)
			if err != nil {
				return err
			}
			for _, el := range arr {
				v := NamedGroup(el)
				if supportedGroups[v] {
					groups = append(groups, v)
				}
			}

		case ETSignatureAlgorithms:
			arr, err := ext.Uint16List(2)
			if err != nil {
				return err
			}
			for _, el := range arr {
				v := SignatureScheme(el)
				if supportedSignatureSchemes[v] {
					signatureSchemes = append(signatureSchemes, v)
				}
			}

		case ETSupportedVersions:
			arr, err := ext.Uint16List(1)
			if err != nil {
				return err
			}
			for _, el := range arr {
				v := ProtocolVersion(el)
				if supportedVersions[v] {
					versions = append(versions, v)
				}
			}

		case ETKeyShare:
			if len(ext.Data) < 2 {
				// XXX should alert on errors
				return fmt.Errorf("%v: invalid data", ext.Type)
			}
			ll := int(bo.Uint16(ext.Data))
			if 2+ll != len(ext.Data) {
				return fmt.Errorf("%v: invalid data", ext.Type)
			}
			for i := 2; i < len(ext.Data); {
				var entry KeyShareEntry
				n, err := UnmarshalFrom(ext.Data[i:], &entry)
				if err != nil {
					return err
				}
				if supportedGroups[entry.Group] && clientKEX == nil {
					clientKEX = &KeyShareEntry{
						Group:       entry.Group,
						KeyExchange: make([]byte, len(entry.KeyExchange)),
					}
					copy(clientKEX.KeyExchange, entry.KeyExchange)
				}

				i += n
			}
		}

		_, ok := tls13Extensions[ext.Type]
		if col%12 == 0 || ok {
			conn.Debugf("\n     ")
			col = 0
		} else {
			conn.Debugf(" ")
		}
		col++

		if ok {
			conn.Debugf("%v", ext)
			col = 12
		} else {
			conn.Debugf("%v", ext)
		}
	}
	if col > 0 {
		conn.Debugf("\n")
	}
	conn.Debugf("   }\n")

	fmt.Printf("versions        : %v\n", versions)
	fmt.Printf("cipherSuites    : %v\n", cipherSuites)
	fmt.Printf("groups          : %v\n", groups)
	fmt.Printf("signatureSchemes: %v\n", signatureSchemes)
	fmt.Printf("clientKEX       : %v\n", clientKEX)

	if len(versions) == 0 || len(cipherSuites) == 0 ||
		len(groups) == 0 || len(signatureSchemes) == 0 {
		// XXX alert
		return fmt.Errorf("no matching algorithms")
	}

	if clientKEX == nil {
		// No matching group, send HelloRetryRequest.
		req := &ServerHello{
			LegacyVersion:   VersionTLS12,
			LegacySessionID: ch.LegacySessionID,
			CipherSuite:     cipherSuites[0],
			Extensions:      []Extension{},
		}
		_, err := rand.Read(req.Random[:])
		if err != nil {
			return err
		}
	}
	return nil
}

// ReadRecord reads a record layer record.
func (conn *Connection) ReadRecord() (ContentType, []byte, error) {
	// Read record header.
	for i := 0; i < 5; {
		n, err := conn.conn.Read(conn.rbuf[i:5])
		if err != nil {
			return CTInvalid, nil, err
		}
		i += n
	}
	fmt.Printf("Record:\n")

	ct := ContentType(conn.rbuf[0])
	legacyVersion := ProtocolVersion(bo.Uint16(conn.rbuf[1:3]))
	length := int(bo.Uint16(conn.rbuf[3:5]))

	fmt.Printf(" - ContentType    : %v\n", ct)
	fmt.Printf(" - ProtocolVersion: %v\n", legacyVersion)
	fmt.Printf(" - length         : %v\n", length)

	for i := 0; i < length; {
		n, err := conn.conn.Read(conn.rbuf[i:length])
		if err != nil {
			return CTInvalid, nil, err
		}
		i += n
	}
	if false {
		fmt.Printf("Data:\n%s", hex.Dump(conn.rbuf[:length]))
		fmt.Printf("%x\n", conn.rbuf[:length])
	}

	return ct, conn.rbuf[:length], nil
}
