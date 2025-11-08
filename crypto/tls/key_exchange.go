//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/markkurossi/ephemelier/crypto/hkdf"
)

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

	var err error

	conn.serverCipher, err = NewCipher(serverHSKey, serverHSIV)
	if err != nil {
		return err
	}
	conn.clientCipher, err = NewCipher(clientHSKey, clientHSIV)
	if err != nil {
		return err
	}

	return nil
}

// Cipher implements an AEAD cipher instance.
type Cipher struct {
	cipher cipher.AEAD
	iv     []byte
	seq    uint64
}

// NewCipher creates a new Cipher for the key and iv.
func NewCipher(key, iv []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		cipher: cipher,
		iv:     iv,
	}, nil
}

// Encrypt encrypts the data. The ct argument specifies the content
// type of the data.
func (cipher *Cipher) Encrypt(ct ContentType, data []byte) []byte {
	// Construct TLSInnerPlaintext:
	//
	// struct {
	//     opaque content[TLSPlaintext.length];
	//     ContentType type;
	//     uint8 zeros[length_of_padding];
	// } TLSInnerPlaintext;
	//
	// struct {
	//     ContentType opaque_type = application_data; /* 23 */
	//     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
	//     uint16 length;
	//     opaque encrypted_record[TLSCiphertext.length];
	// } TLSCiphertext;

	plaintext := make([]byte, len(data)+1)
	copy(plaintext, data)
	plaintext[len(data)] = byte(ct)

	cipherLen := len(plaintext) + cipher.cipher.Overhead()

	// Additional data is the TLS record header.
	var hdr [5]byte
	hdr[0] = byte(CTApplicationData)
	bo.PutUint16(hdr[1:3], uint16(VersionTLS12))
	bo.PutUint16(hdr[3:5], uint16(cipherLen))

	// IV.

	iv := make([]byte, len(cipher.iv))
	copy(iv, cipher.iv)

	var seq [8]byte
	bo.PutUint64(seq[0:], cipher.seq)
	cipher.seq++

	for i := 0; i < len(seq); i++ {
		iv[len(iv)-len(seq)+i] ^= seq[i]
	}

	fmt.Printf("iv : %x\n", cipher.iv)
	fmt.Printf("seq:         %x\n", seq[:])
	fmt.Printf(" =>: %x\n", iv)

	return cipher.cipher.Seal(nil, iv, plaintext, hdr[:])
}
