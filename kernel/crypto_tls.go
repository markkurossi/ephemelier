//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

func (proc *Process) tlsServer(sys *syscall) {
	fd, ok := proc.fds[sys.arg0]
	if !ok {
		sys.SetArg0(int32(-EBADF))
		return
	}
	socketfd, ok := fd.Impl.(*FDSocket)
	if !ok {
		sys.SetArg0(int32(-ENOTSOCK))
		return
	}
	var err error
	if proc.role == RoleGarbler {
		err = proc.tlsServerGarbler(socketfd, sys)
	} else {
		err = proc.tlsServerEvaluator(socketfd, sys)
	}
	if err != nil {
		sys.SetArg0(int32(mapError(err)))
		return
	}
}

func (proc *Process) tlsServerGarbler(sock *FDSocket, sys *syscall) error {
	conn := tls.NewConnection(sock.conn)

	priv, cert, err := LoadKeyAndCert("ephemelier-key.pem",
		"ephemelier-cert.pem")
	if err != nil {
		return err
	}

	err = conn.ServerHandshake(priv, cert)
	if err != nil {
		return err
	}

	sys.SetArg0(-1)
	return nil
}

func (proc *Process) tlsServerEvaluator(sock *FDSocket, sys *syscall) error {
	sys.SetArg0(0)
	return nil
}

// LoadKeyAndCert loads the private key and certificate from PEM files
func LoadKeyAndCert(keyPath, certPath string) (
	*ecdsa.PrivateKey, *x509.Certificate, error) {

	// Load certificate file.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Load private key file.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not ECDSA, got %T",
			parsedKey)
	}

	// Verify that the private key matches the certificate's public key.
	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("certificate public key is not ECDSA")
	}
	if !certPubKey.Equal(&privateKey.PublicKey) {
		return nil, nil,
			fmt.Errorf("private key does not match certificate public key")
	}

	return privateKey, cert, nil
}
