//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/markkurossi/ephemelier/crypto/spdz"
	"github.com/markkurossi/ephemelier/crypto/tls"
)

type tlsMsg uint8

const (
	tlsMsgInit tlsMsg = iota
	tlsMsgKEX
	tlsMsgKEXResult
	tlsMsgError
)

func (msg tlsMsg) String() string {
	name, ok := tlsMsgs[msg]
	if ok {
		return name
	}
	return fmt.Sprintf("{tlsMsg %d}", int(msg))
}

var tlsMsgs = map[tlsMsg]string{
	tlsMsgInit:      "tlsMsgInit",
	tlsMsgKEX:       "tlsMsgKEX",
	tlsMsgKEXResult: "tlsMsgKEXResult",
	tlsMsgError:     "tlsMsgError",
}

// TLSKEX implements the tlsMsgKEX message.
type TLSKEX struct {
	KeyShare []byte
}

// TLSKEXResult implements the tlsMsgKEXResult message.
type TLSKEXResult struct {
	PubkeyX  []byte
	PubkeyY  []byte
	PartialX []byte
	PartialY []byte
}

// TLSError implements the tlsMsgError message.
type TLSError struct {
	Message []byte
	Errno   uint32
}

var (
	curve       = elliptic.P256()
	curveParams = curve.Params()
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

	clientKex, err := conn.ServerHandshake()
	if err != nil {
		proc.tlsPeerErrf(err, "handshake failed: %v", err)
		return err
	}
	peerPublicKey, err := DecodePublicKey(clientKex)
	if err != nil {
		proc.tlsPeerErrf(err, "invalid client public key: %v", err)
		return err
	}

	dhPeer, err := NewDHPeer("Garbler", curve)
	if err != nil {
		proc.tlsPeerErrf(err, "failed to create DH peer: %v", err)
		return err
	}

	// Communicate client public key with evaluator.
	data, err := Marshal(&TLSKEX{
		KeyShare: clientKex,
	})
	if err != nil {
		proc.tlsPeerErrf(err, "failed to marshal message: %v", err)
		return err
	}
	err = proc.conn.SendByte(byte(tlsMsgKEX))
	if err != nil {
		return err
	}
	err = proc.conn.SendData(data)
	if err != nil {
		return err
	}
	err = proc.conn.Flush()
	if err != nil {
		return err
	}

	// Read evaluator's kex result.
	b, err := proc.conn.ReceiveByte()
	if err != nil {
		return err
	}
	proc.debugf("recv %v\n", tlsMsg(b))
	switch tlsMsg(b) {
	case tlsMsgKEXResult:
		data, err = proc.conn.ReceiveData()
		if err != nil {
			return err
		}
		var kexResult TLSKEXResult
		_, err = UnmarshalFrom(data, &kexResult)
		if err != nil {
			proc.tlsPeerErrf(err, "failed to unmarshal message: %v", err)
			return err
		}

		// Compute our public key: α·G = Σ(αᵢ·G)
		pubkeyX, pubkeyY := curve.Add(dhPeer.Pubkey.X, dhPeer.Pubkey.Y,
			new(big.Int).SetBytes(kexResult.PubkeyX),
			new(big.Int).SetBytes(kexResult.PubkeyY))

		// Encode public key into uncompressed SEC 1 format.

		pubkey := make([]byte, 65)
		pubkey[0] = 0x04

		xBytes := pubkeyX.Bytes()
		copy(pubkey[1+32-len(xBytes):], xBytes)

		yBytes := pubkeyY.Bytes()
		copy(pubkey[1+64-len(yBytes):], yBytes)

		// Compute partial DH αᵢ·(β·G)
		partial := dhPeer.ComputePartialDH(peerPublicKey)

		// Compute shared secret αβ·G = Σ(αᵢ·(β·G)) with SPDZ. The
		// function returns our arithmetic share of the secret.
		spdzFinalX, spdzFinalY, err := spdz.P256Add(spdz.Sender, proc.conn,
			partial.X, partial.Y)
		if err != nil {
			proc.tlsPeerErrf(err, "SPDZ P256Add failed: %v", err)
			return err
		}
		_ = spdzFinalY
		fmt.Printf("finalX: %v\n", spdzFinalX.Text(16))

		// Debugging, read evaluator's share.
		data, err = proc.conn.ReceiveData()
		if err != nil {
			return err
		}
		peerSpdzFinalX := new(big.Int).SetBytes(data)
		spdzFinal := add(spdzFinalX, peerSpdzFinalX)

		// Debugging secrets.

		finalX, finalY := curveAdd(partial.X, partial.Y,
			new(big.Int).SetBytes(kexResult.PartialX),
			new(big.Int).SetBytes(kexResult.PartialY))

		fmt.Printf("curveAdd:\n")
		fmt.Printf(" - g.X: %x\n", partial.X.Bytes())
		fmt.Printf(" - g.Y: %x\n", partial.Y.Bytes())
		fmt.Printf(" - e.X: %x\n", kexResult.PartialX)
		fmt.Printf(" - e.Y: %x\n", kexResult.PartialY)
		fmt.Printf(" =>  X: %x\n", finalX.Bytes())
		fmt.Printf(" =>  Y: %x\n", finalY.Bytes())
		fmt.Printf("SPDZ  : %v\n", spdzFinal.Text(16))

		if finalX.Cmp(spdzFinal) == 0 {
			fmt.Println("--SPDZ result match-------------------------------")
		}

		// Write ServerHello and continue from the MCP space.
		data, err := conn.MakeServerHello(pubkey)
		if err != nil {
			proc.tlsPeerErrf(err, "create ServerHello: %v", err)
			return err
		}
		conn.WriteTranscript(data)

		err = conn.WriteRecord(tls.CTHandshake, data)
		if err != nil {
			proc.tlsPeerErrf(err, "write ServerHello: %v", err)
			return err
		}

		// Return TLS FD.
		fd := NewTLSFD(conn, priv, cert)
		sys.SetArg0(proc.AllocFD(fd))

		// Return our share of the shared secret | transcript.
		sys.argBuf = spdzFinalX.Bytes()
		sys.argBuf = append(sys.argBuf, conn.Transcript()...)

		// Sync FD with evaluator.
		err = proc.conn.SendUint32(int(sys.arg0))
		if err == nil {
			err = proc.conn.Flush()
		}
		if err != nil {
			fd.Close()
			proc.FreeFD(sys.arg0)
			sys.arg0 = int32(mapError(err))
		}
		return nil

	case tlsMsgError:
		data, err = proc.conn.ReceiveData()
		if err != nil {
			return err
		}
		var msgError TLSError
		_, err = UnmarshalFrom(data, &msgError)
		if err != nil {
			return err
		}
		proc.debugf("peer error: %v\n", string(msgError.Message))
		sys.SetArg0(-int32(msgError.Errno))
		return nil

	default:
		return fmt.Errorf("unknown message %d from evaluator", b)
	}
}

func (proc *Process) tlsServerEvaluator(sock *FDSocket, sys *syscall) error {
	var dhPeer *DHPeer

	b, err := proc.conn.ReceiveByte()
	if err != nil {
		return err
	}
	proc.debugf("recv %v\n", tlsMsg(b))
	switch tlsMsg(b) {
	case tlsMsgKEX:
		data, err := proc.conn.ReceiveData()
		if err != nil {
			return err
		}
		var msg TLSKEX
		_, err = UnmarshalFrom(data, &msg)
		if err != nil {
			proc.tlsPeerErrf(err, "failed to unmarshal message: %v", err)
			return err
		}
		peerPublicKey, err := DecodePublicKey(msg.KeyShare)
		if err != nil {
			proc.tlsPeerErrf(err, "invalid client public key: %v", err)
			return err
		}
		dhPeer, err = NewDHPeer("Evaluator", curve)
		if err != nil {
			proc.tlsPeerErrf(err, "failed to create DH peer: %v", err)
			return err
		}

		// Compute partial Diffie-Hellman.
		partial := dhPeer.ComputePartialDH(peerPublicKey)

		// XXX return only dhPeer.Pubkey.{X,Y} in TLSKEXResult.
		//
		// XXX end syscall here and return partial to MPC
		// space. Continue the handshake from MPC.

		data, err = Marshal(&TLSKEXResult{
			PubkeyX:  dhPeer.Pubkey.X.Bytes(),
			PubkeyY:  dhPeer.Pubkey.Y.Bytes(),
			PartialX: partial.X.Bytes(),
			PartialY: partial.Y.Bytes(),
		})
		if err != nil {
			proc.tlsPeerErrf(err, "failed to marshal message: %v", err)
			return err
		}
		err = proc.conn.SendByte(byte(tlsMsgKEXResult))
		if err != nil {
			return err
		}
		err = proc.conn.SendData(data)
		if err != nil {
			return err
		}
		err = proc.conn.Flush()
		if err != nil {
			return err
		}

		// Compute shared secret αβ·G = Σ(αᵢ·(β·G)) with SPDZ. The
		// function returns our arithmetic share of the secret.
		spdzFinalX, spdzFinalY, err := spdz.P256Add(spdz.Receiver, proc.conn,
			partial.X, partial.Y)
		if err != nil {
			proc.tlsPeerErrf(err, "SPDZ P256Add failed: %v", err)
			return err
		}
		_ = spdzFinalY
		fmt.Printf("finalX: %v\n", spdzFinalX.Text(16))

		// Debugging, send our share to garbler.
		err = proc.conn.SendData(spdzFinalX.Bytes())
		if err != nil {
			return err
		}
		err = proc.conn.Flush()
		if err != nil {
			return err
		}

		// Return TLS FD.
		fd := NewTLSFD(nil, nil, nil)

		// Get FD from garbler.
		gfd, err := proc.conn.ReceiveUint32()
		if err == nil {
			sys.SetArg0(int32(gfd))

			// Return our share of the shared secret.
			sys.argBuf = spdzFinalX.Bytes()

			err = proc.SetFD(sys.arg0, fd)
		}
		if err != nil {
			fd.Close()
			sys.SetArg0(int32(mapError(err)))
		}

		return nil

	case tlsMsgError:
		data, err := proc.conn.ReceiveData()
		if err != nil {
			return err
		}
		var msgError TLSError
		_, err = UnmarshalFrom(data, &msgError)
		if err != nil {
			return err
		}
		proc.debugf("peer error: %v\n", string(msgError.Message))
		sys.SetArg0(-int32(msgError.Errno))
		return nil

	default:
		return fmt.Errorf("unknown message %d from garbler", b)
	}
}

func (proc *Process) tlsKex(sys *syscall) {
	fd, ok := proc.fds[sys.arg0]
	if !ok {
		sys.SetArg0(int32(-EBADF))
		return
	}
	tlsfd, ok := fd.Impl.(*FDTLS)
	if !ok {
		sys.SetArg0(int32(-ENOTSOCK))
		return
	}
	if proc.role == RoleEvaluator {
		sys.SetArg0(sys.arg1)
		return
	}

	ht := tls.HandshakeType(sys.arg1)

	if len(sys.argBuf) > 0 {
		var appData []byte
		if ht == 0 {
			l := int(sys.argBuf[0])
			if l >= len(sys.argBuf)-1 {
				sys.SetArg0(int32(-EINVAL))
				return
			}
			appData = sys.argBuf[1 : l+1]
			tlsfd.conn.WriteTranscript(sys.argBuf[l+1:])
		} else {
			appData = sys.argBuf
		}
		err := tlsfd.conn.WriteRecord(tls.CTApplicationData, appData)
		if err != nil {
			sys.SetArg0(int32(mapError(err)))
			return
		}
	}

	// Return the message type as arg0.
	sys.SetArg0(int32(ht))

	var data []byte
	var err error

	switch ht {
	case tls.HTEncryptedExtensions:
		data, err = tlsfd.conn.MakeEncryptedExtensions()
		if err != nil {
			sys.SetArg0(int32(mapError(err)))
			return
		}

	case tls.HTCertificate:
		data, err = tlsfd.conn.MakeCertificate()
		if err != nil {
			sys.SetArg0(int32(mapError(err)))
			return
		}

	case tls.HTCertificateVerify:
		data, err = tlsfd.conn.MakeCertificateVerify()
		if err != nil {
			sys.SetArg0(int32(mapError(err)))
			return
		}

	case tls.HTFinished:
		// Set transcript digest directly to argBuf so we don't
		// include it to the transcript. The next call with ct=0
		// contains both the encrypted finished and its plaintext
		// version so we can update the transcript.
		sys.argBuf = tlsfd.conn.Transcript()

	case 0:
		// We just wrote our Finished.

	default:
		fmt.Printf("SysTlskex: invalid handshake: %v\n", ht)
		sys.SetArg0(int32(-EINVAL))
		return
	}

	if len(data) > 0 {
		tlsfd.conn.WriteTranscript(data)
		sys.argBuf = data
	}
}

func (proc *Process) tlsStatus(sys *syscall) {
	fd, ok := proc.fds[sys.arg0]
	if !ok {
		sys.SetArg0(int32(-EBADF))
		return
	}
	tlsfd, ok := fd.Impl.(*FDTLS)
	if !ok {
		sys.SetArg0(int32(-ENOTSOCK))
		return
	}
	tlsfd.handshakeDone = true
	sys.SetArg0(0)
}

func (proc *Process) tlsPeerErrf(err error, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	data, err := Marshal(&TLSError{
		Message: []byte(msg),
		Errno:   uint32(-mapError(err)),
	})
	if err != nil {
		proc.debugf("tlsPeerErrf: Marshal failed: %v\n", err)
		return
	}
	fmt.Printf("tlsMsgError=%v/%d\n", tlsMsgError, int(tlsMsgError))
	err = proc.conn.SendByte(byte(tlsMsgError))
	if err != nil {
		return
	}
	proc.conn.SendData(data)
	proc.conn.Flush()
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

func add(x, y *big.Int) *big.Int {
	r := new(big.Int).Add(x, y)
	return new(big.Int).Mod(r, curveParams.P)
}
