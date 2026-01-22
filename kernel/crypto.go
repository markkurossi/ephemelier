//
// Copyright (c) 2025-2026 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	_ "github.com/markkurossi/ephemelier/crypto/tss"
)

type KeyType int

const (
	KeyTypeAES KeyType = iota
	KeyTypeP256
	KeyTypeChaCha20
)

var KeyTypes = map[KeyType]string{
	KeyTypeAES:      "AES",
	KeyTypeP256:     "P-256",
	KeyTypeChaCha20: "ChaCha20",
}

func (kt KeyType) String() string {
	name, ok := KeyTypes[kt]
	if ok {
		return name
	}
	return fmt.Sprintf("{KeyType %d}", kt)
}

func (kt KeyType) BitSize() (int, error) {
	switch kt {
	case KeyTypeAES:
		return 128, nil
	case KeyTypeP256:
		return 256, nil
	case KeyTypeChaCha20:
		return 256, nil
	default:
		return 0, fmt.Errorf("invalid key type: %v", kt)
	}
}

type keyJSON struct {
	Type        KeyType
	Data        []byte `json:",omitempty"`
	Share       []byte `json:",omitempty"`
	Certificate []byte `json:",omitempty"`
}

type Key struct {
	Type        KeyType
	Data        []byte
	Share       *keygen.LocalPartySaveData
	Certificate *x509.Certificate
}

// Close implements FDImpl.Close.
func (key *Key) Close() int {
	return 0
}

// Read implements FDImpl.Read.
func (key *Key) Read(b []byte) int {
	switch key.Type {
	case KeyTypeAES, KeyTypeChaCha20:
		return copy(b, key.Data)

	default:
		return int(-EBADF)
	}
}

// Write implements FDImpl.Write.
func (key *Key) Write(b []byte) int {
	return int(-EBADF)
}

func (key *Key) Bytes() ([]byte, error) {
	var shareData []byte
	var err error

	if key.Share != nil {
		shareData, err = json.Marshal(key.Share)
		if err != nil {
			return nil, err
		}
	}
	var certData []byte
	if key.Certificate != nil {
		certData = key.Certificate.Raw
	}

	k := &keyJSON{
		Type:        key.Type,
		Data:        key.Data,
		Share:       shareData,
		Certificate: certData,
	}
	return json.Marshal(k)
}

func (proc *Process) keyPath(name string) string {
	name = filepath.Clean(name)
	return filepath.Join(proc.kern.params.Vault, name)
}

func OpenKey(filename string) (*FD, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var k keyJSON
	err = json.Unmarshal(data, &k)
	if err != nil {
		return nil, err
	}

	key := &Key{
		Type: k.Type,
		Data: k.Data,
	}
	if k.Share != nil {
		key.Share = new(keygen.LocalPartySaveData)
		err = json.Unmarshal(k.Share, key.Share)
		if err != nil {
			return nil, err
		}
	}
	if k.Certificate != nil {
		key.Certificate, err = x509.ParseCertificate(k.Certificate)
		if err != nil {
			return nil, err
		}
	}

	return NewFD(key), nil
}
