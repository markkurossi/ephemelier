//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/markkurossi/ephemelier/crypto/hkdf"
)

// HKDF-Extract as per RFC 5869
func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	hash := sha256.New
	extractor := hkdf.New(hash, ikm, salt, nil)
	prk := make([]byte, sha256.Size)
	extractor.Read(prk)
	return prk
}

// HKDF-Expand-Label as per TLS 1.3 spec: 7.1. Key Schedule, page 91
func hkdfExpandLabel(secret []byte, label string, context []byte,
	length int) []byte {

	var hkdfLabel []byte
	if false {
		hkdfLabel = make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
		hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
		hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
		hkdfLabel = append(hkdfLabel, []byte("tls13 ")...)
		hkdfLabel = append(hkdfLabel, []byte(label)...)
		hkdfLabel = append(hkdfLabel, byte(len(context)))
		hkdfLabel = append(hkdfLabel, context...)
	} else {
		// struct {
		//     uint16 length = Length;
		//     opaque label<7..255> = "tls13 " + Label;
		//     opaque context<0..255> = Context;
		// } HkdfLabel;

		tls13 := []byte("tls13 ")
		hkdfLabel = make([]byte, 0, 2+1+len(tls13)+len(label)+1+len(context))
		hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
		hkdfLabel = append(hkdfLabel, byte(len(tls13)+len(label)))
		hkdfLabel = append(hkdfLabel, tls13...)
		hkdfLabel = append(hkdfLabel, []byte(label)...)
		hkdfLabel = append(hkdfLabel, byte(len(context)))
		hkdfLabel = append(hkdfLabel, context...)
	}

	hash := sha256.New
	expander := hkdf.Expand(hash, secret, hkdfLabel)
	out := make([]byte, length)
	io.ReadFull(expander, out)
	return out
}

// Derive secret using HKDF-Expand-Label
func deriveSecretX(secret []byte, label string, messages []byte) []byte {
	hash := sha256.Sum256(messages)
	return hkdfExpandLabel(secret, label, hash[:], sha256.Size)
}

// Derive secret using HKDF-Expand-Label
func deriveSecret(secret []byte, label string, hash []byte) []byte {
	return hkdfExpandLabel(secret, label, hash, sha256.Size)
}

func (conn *Connection) deriveServerHandshakeKeys() error {
	// TLS 1.3 Key Schedule: RFC-8446: 7.1. Key Schedule, page 91-
	fmt.Printf(" - Secrets:\n")

	zeroHash := make([]byte, sha256.Size)
	earlySecret := hkdf.Extract(sha256.New, zeroHash, zeroHash)
	fmt.Printf("   early    : %x\n", earlySecret)

	emptyHash := sha256.Sum256([]byte{})
	derivedSecret := deriveSecret(earlySecret, "derived", emptyHash[:])
	fmt.Printf("   derived  : %x\n", derivedSecret)

	handshakeSecret := hkdf.Extract(sha256.New, conn.sharedSecret,
		derivedSecret)
	fmt.Printf("   handshake: %x\n", handshakeSecret)

	// Derive handshake traffic secrets.
	transcript := conn.transcript.Sum(nil)
	clientHandshakeTrafficSecret := deriveSecret(handshakeSecret,
		"c hs traffic", transcript)
	serverHandshakeTrafficSecret := deriveSecret(handshakeSecret,
		"s hs traffic", transcript)
	fmt.Printf("   c-hs-tr  : %x\n", clientHandshakeTrafficSecret)
	fmt.Printf("   s-hs-tr  : %x\n", serverHandshakeTrafficSecret)

	// Derive keys and IVs from traffic secrets.

	clientHSKey := hkdfExpandLabel(clientHandshakeTrafficSecret, "key", nil, 16)
	clientHSIV := hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", nil, 12)

	fmt.Printf("   c-hs-key : %x\n", clientHSKey)
	fmt.Printf("   c-hs-iv  : %x\n", clientHSIV)

	serverHSKey := hkdfExpandLabel(serverHandshakeTrafficSecret, "key", nil, 16)
	serverHSIV := hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", nil, 12)

	fmt.Printf("   s-hs-key : %x\n", serverHSKey)
	fmt.Printf("   s-hs-iv  : %x\n", serverHSIV)

	return nil
}
