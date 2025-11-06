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
	"errors"
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

	// KEX.
	clientHello      *ClientHello
	versions         []ProtocolVersion
	cipherSuites     []CipherSuite
	groups           []NamedGroup
	signatureSchemes []SignatureScheme
	clientKEX        *KeyShareEntry
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

func (conn *Connection) readHandshakeMsg() (ContentType, []byte, error) {
	for {
		ct, data, err := conn.ReadRecord()
		if err != nil {
			return CTInvalid, nil, err
		}
		switch ct {
		case CTChangeCipherSpec:
			err = conn.recvChangeCipherSpec(data)
			if err != nil {
				return CTInvalid, nil, err
			}
		case CTAlert:
			err = conn.recvAlert(data)
			if err != nil {
				return CTInvalid, nil, err
			}
		case CTHandshake:
			return ct, data, nil
		default:
			return CTInvalid, nil,
				fmt.Errorf("unexpected handshake message: %v", ct)
		}
	}
}

func (conn *Connection) writeHandshakeMsg(ht HandshakeType, data []byte) error {
	// Set TypeLen
	typeLen := uint32(ht)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)

	return conn.WriteRecord(CTHandshake, data)
}

// ServerHandshake runs the server handshake protocol.
func (conn *Connection) ServerHandshake() error {
	//  Client                                               Server
	//
	//  ClientHello
	//  + key_share             -------->
	//                                            HelloRetryRequest
	//                          <--------               + key_share
	//  ClientHello
	//  + key_share             -------->
	//                                                  ServerHello
	//                                                  + key_share
	//                                        {EncryptedExtensions}
	//                                        {CertificateRequest*}
	//                                               {Certificate*}
	//                                         {CertificateVerify*}
	//                                                   {Finished}
	//                          <--------       [Application Data*]
	//  {Certificate*}
	//  {CertificateVerify*}
	//  {Finished}              -------->
	//  [Application Data]      <------->        [Application Data]
	//
	//       Figure 2: Message Flow for a Full Handshake with
	//                     Mismatched Parameters

	_, data, err := conn.readHandshakeMsg()
	if err != nil {
		return err
	}
	err = conn.recvClientHandshake(data)
	if err != nil {
		return err
	}
	if conn.clientKEX == nil {
		// No matching group, send HelloRetryRequest.
		req := &ServerHello{
			LegacyVersion:   VersionTLS12,
			Random:          HelloRetryRequestRandom,
			LegacySessionID: conn.clientHello.LegacySessionID,
			CipherSuite:     conn.cipherSuites[0],
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
		data, err = Marshal(req)
		if err != nil {
			return conn.internalErrorf("marshal failed: %v", err)
		}
		err = conn.writeHandshakeMsg(HTServerHello, data)
		if err != nil {
			return conn.internalErrorf("write failed: %v", err)
		}

		// Read ClientHello.
		_, data, err := conn.readHandshakeMsg()
		if err != nil {
			return err
		}
		err = conn.recvClientHandshake(data)
		if err != nil {
			return err
		}
		if conn.clientKEX == nil {
			return conn.alert(AlertHandshakeFailure)
		}
	}

	// ServerHello

	conn.curve = ecdh.P256()
	conn.privateKey, err = conn.curve.GenerateKey(rand.Reader)
	if err != nil {
		return conn.internalErrorf("error creating private key: %v", err)
	}

	keyShare := &KeyShareEntry{
		Group:       GroupSecp256r1,
		KeyExchange: conn.privateKey.PublicKey().Bytes(),
	}
	req := &ServerHello{
		LegacyVersion:   VersionTLS12,
		LegacySessionID: conn.clientHello.LegacySessionID,
		CipherSuite:     conn.cipherSuites[0],
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
				Data: keyShare.Bytes(),
			},
		},
	}
	_, err = rand.Read(req.Random[:])
	if err != nil {
		return conn.internalErrorf("failed to create random: %v", err)
	}
	fmt.Printf("ServerHello: %v\n", req)
	data, err = Marshal(req)
	if err != nil {
		return conn.internalErrorf("marshal failed: %v", err)
	}

	err = conn.writeHandshakeMsg(HTServerHello, data)
	if err != nil {
		return conn.internalErrorf("write failed: %v", err)
	}

	for {
		ct, data, err := conn.ReadRecord()
		if err != nil {
			return err
		}
		switch ct {
		case CTHandshake:
			err := conn.recvClientHandshake(data)
			if err != nil {
				return err
			}
		case CTChangeCipherSpec:
			err := conn.recvChangeCipherSpec(data)
			if err != nil {
				return err
			}
		case CTAlert:
			err := conn.recvAlert(data)
			if err != nil {
				return err
			}
		default:
			return conn.illegalParameterf("unexpected record %v", ct)
		}
	}
}

func (conn *Connection) recvClientHandshake(data []byte) error {
	if len(data) < 4 {
		return conn.decodeErrorf("truncated handshake")
	}
	typeLen := bo.Uint32(data)
	ht := HandshakeType(typeLen >> 24)
	length := typeLen & 0xffffff
	if int(length+4) != len(data) {
		return conn.decodeErrorf(
			"handshake length mismatch: got %v, expected %v",
			length+4, len(data))
	}
	if ht != HTClientHello {
		return conn.illegalParameterf("invalid handshake: got %v, expected %v",
			ht, HTClientHello)
	}
	return conn.recvClientHello(data)
}

func (conn *Connection) recvClientHello(data []byte) error {
	conn.clientHello = new(ClientHello)
	consumed, err := UnmarshalFrom(data, conn.clientHello)
	if err != nil {
		return err
	}
	if consumed != len(data) {
		return conn.decodeErrorf("trailing data after client_hello: len=%v",
			len(data)-consumed)
	}

	conn.Debugf("client_hello:\n")
	conn.Debugf(" - random: %x\n", conn.clientHello.Random)

	conn.Debugf(" - cipher_suites: {")
	var col int
	for _, suite := range conn.clientHello.CipherSuites {
		if supportedCipherSuites[suite] {
			conn.cipherSuites = append(conn.cipherSuites, suite)
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
	for _, ext := range conn.clientHello.Extensions {
		switch ext.Type {
		case ETSupportedGroups:
			arr, err := ext.Uint16List(2)
			if err != nil {
				return conn.decodeErrorf("invalid extension: %v", err)
			}
			for _, el := range arr {
				v := NamedGroup(el)
				if supportedGroups[v] {
					conn.groups = append(conn.groups, v)
				}
			}

		case ETSignatureAlgorithms:
			arr, err := ext.Uint16List(2)
			if err != nil {
				return conn.decodeErrorf("invalid extension: %v", err)
			}
			for _, el := range arr {
				v := SignatureScheme(el)
				if supportedSignatureSchemes[v] {
					conn.signatureSchemes = append(conn.signatureSchemes, v)
				}
			}

		case ETSupportedVersions:
			arr, err := ext.Uint16List(1)
			if err != nil {
				return conn.decodeErrorf("invalid extension: %v", err)
			}
			for _, el := range arr {
				v := ProtocolVersion(el)
				if supportedVersions[v] {
					conn.versions = append(conn.versions, v)
				}
			}

		case ETKeyShare:
			if len(ext.Data) < 2 {
				return conn.decodeErrorf("%v: invalid data", ext.Type)
			}
			ll := int(bo.Uint16(ext.Data))
			if 2+ll != len(ext.Data) {
				return conn.decodeErrorf("%v: invalid data", ext.Type)
			}
			for i := 2; i < len(ext.Data); {
				var entry KeyShareEntry
				n, err := UnmarshalFrom(ext.Data[i:], &entry)
				if err != nil {
					return conn.decodeErrorf("%v: invalid data: %v",
						ext.Type, err)
				}
				if supportedGroups[entry.Group] && conn.clientKEX == nil {
					conn.clientKEX = &KeyShareEntry{
						Group:       entry.Group,
						KeyExchange: make([]byte, len(entry.KeyExchange)),
					}
					copy(conn.clientKEX.KeyExchange, entry.KeyExchange)
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

	fmt.Printf("versions        : %v\n", conn.versions)
	fmt.Printf("cipherSuites    : %v\n", conn.cipherSuites)
	fmt.Printf("groups          : %v\n", conn.groups)
	fmt.Printf("signatureSchemes: %v\n", conn.signatureSchemes)
	fmt.Printf("clientKEX       : %v\n", conn.clientKEX)

	if len(conn.versions) == 0 {
		return conn.alert(AlertProtocolVersion)
	}
	if len(conn.cipherSuites) == 0 || len(conn.groups) == 0 ||
		len(conn.signatureSchemes) == 0 {
		return conn.alert(AlertHandshakeFailure)
	}

	return nil
}

func (conn *Connection) recvChangeCipherSpec(data []byte) error {
	if len(data) != 1 || data[0] != 1 {
		return conn.decodeErrorf("invalid change_cipher_spec")
	}
	return nil
}

func (conn *Connection) recvAlert(data []byte) error {
	if len(data) != 2 {
		return conn.decodeErrorf("invalid alert")
	}
	desc := AlertDescription(data[1])
	fmt.Printf("alert: %v: %v\n", desc.Level(), desc)
	return nil
}

func (conn *Connection) alert(desc AlertDescription) error {
	var buf [2]byte

	buf[0] = byte(desc.Level())
	buf[1] = byte(desc)

	return conn.WriteRecord(CTAlert, buf[:])
}

func (conn *Connection) decodeErrorf(msg string, a ...interface{}) error {
	orig := fmt.Errorf(msg, a...)
	err := conn.alert(AlertDecodeError)
	if err != nil {
		return errors.Join(err, orig)
	}
	return orig
}

func (conn *Connection) illegalParameterf(msg string, a ...interface{}) error {
	orig := fmt.Errorf(msg, a...)
	err := conn.alert(AlertIllegalParameter)
	if err != nil {
		return errors.Join(err, orig)
	}
	return orig
}

func (conn *Connection) internalErrorf(msg string, a ...interface{}) error {
	orig := fmt.Errorf(msg, a...)
	err := conn.alert(AlertInternalError)
	if err != nil {
		return errors.Join(err, orig)
	}
	return orig
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
