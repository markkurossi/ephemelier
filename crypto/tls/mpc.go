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

func (conn *Conn) MPCWrite(ct ContentType, plain, cipher []byte) error {
	if len(plain) > 0 {
		conn.transcript.Write(plain)
	}
	if len(cipher) > 0 {
		return conn.WriteRecord(ct, cipher)
	}

	return conn.WriteRecord(ct, plain)
}
