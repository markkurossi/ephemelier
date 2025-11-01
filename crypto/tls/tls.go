//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto/ecdh"
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
	conn       net.Conn
	rbuf       []byte
	curve      ecdh.Curve
	privateKey *ecdh.PrivateKey
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
	consumed, err := UnmarshalFrom(handshake, &ch)
	if err != nil {
		return err
	}
	if consumed != len(handshake) {
		return fmt.Errorf("trailing data after client_hello: len=%v",
			len(handshake)-consumed)
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

	conn.curve = ecdh.P256()
	conn.privateKey, err = conn.curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if clientKEX == nil {
		// No matching group, send HelloRetryRequest.

		keyShare := &KeyShareEntry{
			Group:       GroupSecp256r1,
			KeyExchange: conn.privateKey.PublicKey().Bytes(),
		}
		_ = keyShare

		req := &ServerHello{
			LegacyVersion:   VersionTLS12,
			Random:          HelloRetryRequestRandom,
			LegacySessionID: ch.LegacySessionID,
			CipherSuite:     cipherSuites[0],
			Extensions: []Extension{
				// XXX Other extensions (see Section 4.2) are sent
				// separately in the EncryptedExtensions message.
				//NewExtension(ETSignatureAlgorithms,
				//SigSchemeEcdsaSecp256r1Sha256),
				Extension{
					Type: ETSupportedVersions,
					Data: VersionTLS13.Bytes(),
				},
				Extension{
					Type: ETKeyShare,
					Data: GroupSecp256r1.Bytes(),
				},
			},
		}
		fmt.Printf("HelloRetryRequest: %v\n", req)
		data, err := Marshal(req)
		if err != nil {
			return err
		}

		// Set TypeLen
		typeLen := uint32(HTServerHello)<<24 | uint32(len(data)-4)
		bo.PutUint32(data[0:4], typeLen)

		fmt.Printf("typeLen=%08x\n", typeLen)

		// Try to decode the data.
		var sh ServerHello
		consumed, err = UnmarshalFrom(data, &sh)
		if err != nil {
			fmt.Printf("UnmarshalFrom failed: %v: consumed=%v\n", err, consumed)
			fmt.Printf("ch: %v\n", sh)
			return err
		}
		fmt.Printf("sh: %v\n", sh)
		fmt.Printf(" - consumed: %v\n", consumed)

		err = conn.WriteRecord(CTHandshake, data)
		if err != nil {
			return err
		}

		ct, data, err := conn.ReadRecord()
		if err != nil {
			return err
		}
		fmt.Printf("ct=%v\n", ct)

		ct, data, err = conn.ReadRecord()
		if err != nil {
			return err
		}
		fmt.Printf("ct=%v\n", ct)
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

// WriteRecord writes a record layer record.
func (conn *Connection) WriteRecord(ct ContentType, data []byte) error {
	var hdr [5]byte

	fmt.Printf("len(data)=%v\n", len(data))

	hdr[0] = byte(ct)
	bo.PutUint16(hdr[1:3], uint16(VersionTLS12))
	bo.PutUint16(hdr[3:5], uint16(len(data)))

	fmt.Printf("WriteRecord: hdr:\n%s", hex.Dump(hdr[:]))

	_, err := conn.conn.Write(hdr[:])
	if err != nil {
		return err
	}
	_, err = conn.conn.Write(data)
	return err
}
