//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"fmt"
)

// ContentType specifies record layer record types.
type ContentType uint8

// Record layer record types.
const (
	CTInvalid          ContentType = 0
	CTChangeCipherSpec ContentType = 20
	CTAlert            ContentType = 21
	CTHandshake        ContentType = 22
	CTApplicationData  ContentType = 23
)

func (ct ContentType) String() string {
	name, ok := contentTypes[ct]
	if ok {
		return name
	}
	return fmt.Sprintf("{ContentType %d}", ct)
}

var contentTypes = map[ContentType]string{
	CTInvalid:          "invalid",
	CTChangeCipherSpec: "change_cipher_spec",
	CTAlert:            "alert",
	CTHandshake:        "handshake",
	CTApplicationData:  "application_data",
}

// ProtocolVersion defines TLS protocol version.
type ProtocolVersion uint16

func (v ProtocolVersion) String() string {
	name, ok := protocolVersions[v]
	if ok {
		return name
	}
	return fmt.Sprintf("%04x", uint(v))
}

var protocolVersions = map[ProtocolVersion]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

// HandshakeType defines handshake message types.
type HandshakeType uint8

// Handshake message types.
const (
	HTClientHello HandshakeType = iota + 1
	HTServerHello
	_
	HTNewSessionTicket
	HTEndOfEarlyData
	_
	_
	HTEncryptedExtensions
	_
	_
	HTCertificate
	_
	HTCertificateRequest
	_
	HTCertificateVerify
	_
	_
	_
	_
	HTFinished
	_
	_
	_
	HTKeyUpdate
)

func (ht HandshakeType) String() string {
	name, ok := handshakeTypes[ht]
	if ok {
		return name
	}
	return fmt.Sprintf("{HandshakeType %d}", ht)
}

var handshakeTypes = map[HandshakeType]string{
	HTClientHello:         "client_hello",
	HTServerHello:         "server_hello",
	HTNewSessionTicket:    "new_session_ticket",
	HTEndOfEarlyData:      "end_of_early_data",
	HTEncryptedExtensions: "encrypted_extensions",
	HTCertificate:         "certificate",
	HTCertificateRequest:  "certificate_request",
	HTCertificateVerify:   "certificate_verify",
	HTFinished:            "finished",
	HTKeyUpdate:           "key_update",
}

// ClientHello implements the client_hello message.
type ClientHello struct {
	LegacyVersion            ProtocolVersion
	Random                   [32]byte
	LegacySessionID          []byte        `tls:"u8"`
	CipherSuites             []CipherSuite `tls:"u16"`
	LegacyCompressionMethods []byte        `tls:"u8"`
	Extensions               []Extension   `tls:"u16"`
}

// CipherSuite defines cipher suites.
type CipherSuite uint16

func (cs CipherSuite) String() string {
	name, ok := tls13CipherSuites[cs]
	if ok {
		return name
	}
	return fmt.Sprintf("{CipherSuite 0x%02x,0x%02x}", int(cs>>8), int(cs&0xff))
}

var tls13CipherSuites = map[CipherSuite]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

// NamedGroup defines named key exchange groups.
type NamedGroup uint16

// Named groups.
const (
	GroupSecp256r1      NamedGroup = 0x0017
	GroupSecp384r1      NamedGroup = 0x0018
	GroupSecp521r1      NamedGroup = 0x0019
	GroupX25519         NamedGroup = 0x001D
	GroupX448           NamedGroup = 0x001E
	GroupFfdhe2048      NamedGroup = 0x0100
	GroupFfdhe3072      NamedGroup = 0x0101
	GroupFfdhe4096      NamedGroup = 0x0102
	GroupFfdhe6144      NamedGroup = 0x0103
	GroupFfdhe8192      NamedGroup = 0x0104
	GroupX25519MLKEM768 NamedGroup = 0x11EC
)

func (group NamedGroup) String() string {
	name, ok := tls13NamedGroups[group]
	if ok {
		return name
	}
	return fmt.Sprintf("%04x", int(group))
}

var tls13NamedGroups = map[NamedGroup]string{
	GroupSecp256r1:      "secp256r1",
	GroupSecp384r1:      "secp384r1",
	GroupSecp521r1:      "secp521r1",
	GroupX25519:         "x25519",
	GroupX25519MLKEM768: "X25519MLKEM768",
}

// SignatureScheme defines the signature algorithms for the
// signature_algorithms and signature_algorithms_cert extensions.
type SignatureScheme uint16

// Signature algorithms.
const (
	SigSchemeRsaPkcs1Sha256       SignatureScheme = 0x0401
	SigSchemeRsaPkcs1Sha384       SignatureScheme = 0x0501
	SigSchemeRsaPkcs1Sha512       SignatureScheme = 0x0601
	SigSchemeEcdsaSecp256r1Sha256 SignatureScheme = 0x0403
	SigSchemeEcdsaSecp384r1Sha384 SignatureScheme = 0x0503
	SigSchemeEcdsaSecp521r1Sha512 SignatureScheme = 0x0603
	SigSchemeRsaPssRsaeSha256     SignatureScheme = 0x0804
	SigSchemeRsaPssRsaeSha384     SignatureScheme = 0x0805
	SigSchemeRsaPssRsaeSha512     SignatureScheme = 0x0806
	SigSchemeEd25519              SignatureScheme = 0x0807
	SigSchemeEd448                SignatureScheme = 0x0808
	SigSchemeRsaPssPssSha256      SignatureScheme = 0x0809
	SigSchemeRsaPssPssSha384      SignatureScheme = 0x080a
	SigSchemeRsaPssPssSha512      SignatureScheme = 0x080b
	SigSchemeRsaPkcs1Sha1         SignatureScheme = 0x0201
	SigSchemeEcdsaSha1            SignatureScheme = 0x0203
)

func (scheme SignatureScheme) String() string {
	name, ok := tls13SignatureSchemes[scheme]
	if ok {
		return name
	}

	return fmt.Sprintf("%04x", int(scheme))
}

var tls13SignatureSchemes = map[SignatureScheme]string{
	SigSchemeRsaPkcs1Sha256:       "rsa_pkcs1_sha256",
	SigSchemeRsaPssRsaeSha256:     "rsa_pss_rsae_sha256",
	SigSchemeEcdsaSecp256r1Sha256: "ecdsa_secp256r1_sha256",
}

// KeyShareEntry defines a key_share extension entry.
type KeyShareEntry struct {
	Group       NamedGroup
	KeyExchange []byte `tls:"u16"`
}

// Extension defines handshake extensions.
type Extension struct {
	Type ExtensionType
	Data []byte `tls:"u16"`
}

func (ext Extension) String() string {
	switch ext.Type {
	case ETSupportedGroups:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		ll := int(bo.Uint16(ext.Data))
		if 2+ll != len(ext.Data) || ll%2 != 0 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)
		for i := 2; i < 2+ll; i += 2 {
			val := NamedGroup(bo.Uint16(ext.Data[i:]))
			result += fmt.Sprintf(" %v", val)
		}
		return result

	case ETSignatureAlgorithms:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		ll := int(bo.Uint16(ext.Data))
		if 2+ll != len(ext.Data) || ll%2 != 0 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)
		for i := 2; i < 2+ll; i += 2 {
			val := SignatureScheme(bo.Uint16(ext.Data[i:]))
			result += fmt.Sprintf(" %v", val)
		}
		return result

	case ETSupportedVersions:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		if len(ext.Data) == 2 {
			// ServerHello.
			return ProtocolVersion(bo.Uint16(ext.Data)).String()
		}
		ll := int(ext.Data[0])
		if 1+ll != len(ext.Data) || ll%2 != 0 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}
		result := fmt.Sprintf("%v:", ext.Type)
		for i := 1; i < 1+ll; i += 2 {
			val := ProtocolVersion(bo.Uint16(ext.Data[i:]))
			result += fmt.Sprintf(" %v", val)
		}
		return result

	case ETKeyShare:
		if len(ext.Data) < 2 {
			return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
		}

		result := fmt.Sprintf("%v:", ext.Type)

		ll := int(bo.Uint16(ext.Data))
		if 2+ll == len(ext.Data) {
			// ClientHello.
			ofs := 2
			for ofs < len(ext.Data) {
				var entry KeyShareEntry
				n, err := UnmarshalFrom(ext.Data[ofs:], &entry)
				if err != nil {
					return fmt.Sprintf("%v: \u26A0 %x", ext.Type, ext.Data)
				}
				result += fmt.Sprintf(" %v[%d]",
					entry.Group, len(entry.KeyExchange))
				ofs += n
			}
		} else {
			// ServerHello.
			return ProtocolVersion(bo.Uint16(ext.Data)).String()
		}
		return result

	default:
		return fmt.Sprintf("%04x", int(ext.Type))
	}
}

// ExtensionType defines the handshake protocol extensions.
type ExtensionType uint16

// ExtensionTypes.
const (
	ETServerName                          ExtensionType = 0     // RFC 6066
	ETMaxFragmentLength                   ExtensionType = 1     // RFC 6066
	ETStatusRequest                       ExtensionType = 5     // RFC 6066
	ETSupportedGroups                     ExtensionType = 10    // RFC 8422 7919
	ETECPointFormats                      ExtensionType = 11    // RFC 8422
	ETSignatureAlgorithms                 ExtensionType = 13    // RFC 8446
	ETUseSRTP                             ExtensionType = 14    // RFC 5764
	ETHeartbeat                           ExtensionType = 15    // RFC 6520
	ETApplicationLayerProtocolNegotiation ExtensionType = 16    // RFC 7301
	ETSignedCertificateTimestamp          ExtensionType = 18    // RFC 6962
	ETClientCertificateType               ExtensionType = 19    // RFC 7250
	ETServerCertificateType               ExtensionType = 20    // RFC 7250
	ETPadding                             ExtensionType = 21    // RFC 7685
	ETExtendedMasterSecret                ExtensionType = 23    // RFC 7627
	ETCompressCertificate                 ExtensionType = 27    // RFC 8879
	ETSessionTicket                       ExtensionType = 35    // RFC 8446
	ETPreSharedKey                        ExtensionType = 41    // RFC 8446
	ETEarlyData                           ExtensionType = 42    // RFC 8446
	ETSupportedVersions                   ExtensionType = 43    // RFC 8446
	ETCookie                              ExtensionType = 44    // RFC 8446
	ETPSKKeyExchangeModes                 ExtensionType = 45    // RFC 8446
	ETCertificateAuthorities              ExtensionType = 47    // RFC 8446
	ETOIDFilters                          ExtensionType = 48    // RFC 8446
	ETPostHandshakeAuth                   ExtensionType = 49    // RFC 8446
	ETSignatureAlgorithmsCert             ExtensionType = 50    // RFC 8446
	ETKeyShare                            ExtensionType = 51    // RFC 8446
	ETRenegotiationInfo                   ExtensionType = 65281 // RFC 5746
)

func (et ExtensionType) String() string {
	name, ok := tls13Extensions[et]
	if ok {
		return name
	}
	name, ok = extensionTypeNames[et]
	if ok {
		return name
	}
	return fmt.Sprintf("{ExtensionType %d}", et)
}

var tls13Extensions = map[ExtensionType]string{
	ETSupportedVersions:   "supported_versions",
	ETSignatureAlgorithms: "signature_algorithms",
	ETSupportedGroups:     "supported_groups",
	ETKeyShare:            "key_share",
	ETPreSharedKey:        "pre_shared_key",
	ETPSKKeyExchangeModes: "psk_key_exchange_modes",
}

var extensionTypeNames = map[ExtensionType]string{
	ETServerName:                          "server_name",
	ETMaxFragmentLength:                   "max_fragment_length",
	ETStatusRequest:                       "status_request",
	ETECPointFormats:                      "ec_point_formats",
	ETUseSRTP:                             "use_srtp",
	ETHeartbeat:                           "heartbeat",
	ETApplicationLayerProtocolNegotiation: "applicationlayer_protocol_negotiation",
	ETSignedCertificateTimestamp:          "signed_certificate_timestamp",
	ETClientCertificateType:               "client_certificate_type",
	ETServerCertificateType:               "server_certificate_type",
	ETPadding:                             "padding",
	ETExtendedMasterSecret:                "extended_master_secret",
	ETCompressCertificate:                 "compress_certificate",
	ETSessionTicket:                       "session_ticket",
	ETEarlyData:                           "early_data",
	ETCookie:                              "cookie",
	ETCertificateAuthorities:              "certificate_authorities",
	ETOIDFilters:                          "oid_filters",
	ETPostHandshakeAuth:                   "post_handshake_auth",
	ETSignatureAlgorithmsCert:             "signature_algorithms_cert",
	ETRenegotiationInfo:                   "renegotiation_info",
}
