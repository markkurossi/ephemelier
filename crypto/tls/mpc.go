//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto"
	"crypto/rand"
)

// MakeServerHello makes the server_hello message.
func (conn *Conn) MakeServerHello(kex []byte) ([]byte, error) {
	keyShare := &KeyShareEntry{
		Group:       GroupSecp256r1,
		KeyExchange: kex,
	}
	req := &ServerHello{
		LegacyVersion:   VersionTLS12,
		LegacySessionID: conn.clientHello.LegacySessionID,
		CipherSuite:     conn.cipherSuites[0],
		Extensions: []Extension{
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
	_, err := rand.Read(req.Random[:])
	if err != nil {
		return nil, conn.internalErrorf("failed to create random: %v", err)
	}
	data, err := Marshal(req)
	if err != nil {
		return nil, err
	}

	// Set TypeLen
	typeLen := uint32(HTServerHello)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)
	return data, nil
}

// MakeEncryptedExtensions makes the encrypted_extensions message.
func (conn *Conn) MakeEncryptedExtensions() ([]byte, error) {
	// EncryptedExtensions.
	msg := &EncryptedExtensions{
		Extensions: []Extension{},
	}
	data, err := Marshal(msg)
	if err != nil {
		return nil, err
	}
	// Set TypeLen
	typeLen := uint32(HTEncryptedExtensions)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)
	return data, nil
}

// MakeCertificate makes the certificate message.
func (conn *Conn) MakeCertificate() ([]byte, error) {
	// Certificate.
	msgCertificate := &Certificate{
		CertificateList: []CertificateEntry{
			CertificateEntry{
				Data: conn.config.Certificate.Raw,
			},
		},
	}
	data, err := Marshal(msgCertificate)
	if err != nil {
		return nil, err
	}
	// Set TypeLen
	typeLen := uint32(HTCertificate)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)
	return data, nil
}

// MakeCertificateVerify makes the certificate_verify message.
func (conn *Conn) MakeCertificateVerify() ([]byte, error) {
	hashFunc := crypto.SHA256
	digest := conn.certificateVerify(hashFunc)
	signature, err := conn.config.PrivateKey.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return nil, err
	}
	msgCertVerify := &CertificateVerify{
		Algorithm: conn.signatureSchemes[0],
		Signature: signature,
	}
	data, err := Marshal(msgCertVerify)
	if err != nil {
		return nil, err
	}
	// Set TypeLen
	typeLen := uint32(HTCertificateVerify)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)
	return data, nil
}

// MakeFinished makes the finished message.
func (conn *Conn) MakeFinished(server bool) ([]byte, error) {
	verifyData := conn.finished(server)
	var vd32 [32]byte
	copy(vd32[0:], verifyData)
	finished := &Finished{
		VerifyData: vd32,
	}
	data, err := Marshal(finished)
	if err != nil {
		return nil, err
	}
	// Set TypeLen
	typeLen := uint32(HTFinished)<<24 | uint32(len(data)-4)
	bo.PutUint32(data[0:4], typeLen)
	return data, nil
}
