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
	priv, cert, err := LoadKeyAndCert("ephemelier-key.pem",
		"ephemelier-cert.pem")
	if err != nil {
		return err
	}

	conn := tls.NewConnection(sock.conn, &tls.Config{
		PrivateKey:  priv,
		Certificate: cert,
	})

	// XXX priv and cert are in config.
	err = conn.ServerHandshake(priv, cert)
	if err != nil {
		return err
	}

	var buf [4096]byte

	n, err := conn.Read(buf[:])
	if err != nil {
		return err
	}
	fmt.Printf("read: %s\n", buf[:n])

	n, err = conn.Write([]byte("Hello, world!\n"))
	if err != nil {
		return err
	}
	_ = n

	sys.SetArg0(0)

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

var tlsAlertToErrno = map[tls.AlertDescription]Errno{
	// Clean closure - no error.
	tls.AlertCloseNotify: 0,

	// Protocol/format errors.
	tls.AlertUnexpectedMessage:    EPROTO,          // Protocol error
	tls.AlertBadRecordMAC:         EBADMSG,         // Bad message
	tls.AlertRecordOverflow:       EMSGSIZE,        // Message too long
	tls.AlertDecodeError:          EBADMSG,         // Bad message
	tls.AlertIllegalParameter:     EINVAL,          // Invalid argument
	tls.AlertProtocolVersion:      EPROTONOSUPPORT, // Protocol not supported
	tls.AlertMissingExtension:     EPROTO,          // Protocol error
	tls.AlertUnsupportedExtension: EOPNOTSUPP,      // Operation not supported
	tls.AlertUnrecognizedName:     ENOENT,          // No such entry (SNI)

	// Handshake failures.
	tls.AlertHandshakeFailure:      ECONNABORTED, // Connection aborted
	tls.AlertInappropriateFallback: EPROTO,       // Protocol error

	// Certificate errors.
	tls.AlertBadCertificate:               EAUTH,      // Authentication error
	tls.AlertUnsupportedCertificate:       EOPNOTSUPP, // Operation not supported
	tls.AlertCertificateRevoked:           EAUTH,      // Authentication error
	tls.AlertCertificateExpired:           ETIMEDOUT,  // Timed out
	tls.AlertCertificateUnknown:           EAUTH,      // Authentication error
	tls.AlertUnknownCA:                    EAUTH,      // Authentication error
	tls.AlertCertificateRequired:          EAUTH,      // Authentication error
	tls.AlertBadCertificateStatusResponse: EAUTH,      // Authentication error

	// Access/permission errors.
	tls.AlertAccessDenied: EACCES, // Permission denied

	// Security errors.
	tls.AlertDecryptError:         EAUTH, // Authentication error
	tls.AlertInsufficientSecurity: EAUTH, // Authentication error
	tls.AlertUnknownPSKIdentity:   EAUTH, // Authentication error

	// Internal/resource errors.
	tls.AlertInternalError: EFAULT, // Internal error

	// User/application errors.
	tls.AlertUserCanceled:          ECANCELED,       // Operation canceled
	tls.AlertNoApplicationProtocol: EPROTONOSUPPORT, // Protocol not supported
}
