//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/markkurossi/ephemelier/crypto/tss"
	"github.com/markkurossi/ephemelier/kernel"
)

func main() {
	t := flag.String("t", "", "key type")
	out := flag.String("o", "", "output filename")
	flag.Parse()

	log.SetFlags(0)

	if len(*out) == 0 {
		log.Fatalf("no output filename")
	}
	if len(*t) == 0 {
		log.Fatalf("no key type")
	}
	var keyType kernel.KeyType
	var match bool
	for k, v := range kernel.KeyTypes {
		if strings.EqualFold(v, *t) {
			keyType = k
			match = true
		}
	}
	if !match {
		log.Fatalf("invalid key type %v", *t)
	}

	if len(flag.Args()) == 0 {
		log.Fatalf("usage: vault import/create arg...")
	}

	switch flag.Args()[0] {
	case "import":
		err := importFiles(*out, keyType, flag.Args()[1:])
		if err != nil {
			log.Fatal(err)
		}

	case "create":
		err := create(*out, keyType)
		if err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatalf("invalid command: %v\n", flag.Args()[0])
	}
}

func importFiles(filename string, keyType kernel.KeyType, args []string) error {
	key := &kernel.Key{
		Type: keyType,
	}

	for _, arg := range args {
		if strings.HasSuffix(arg, ".share") {
			share, err := tss.ReadSaveData(arg)
			if err != nil {
				return err
			}
			key.Share = share
		} else if strings.HasSuffix(arg, ".pem") {
			certPEM, err := os.ReadFile(arg)
			if err != nil {
				return err
			}
			certBlock, _ := pem.Decode(certPEM)
			if certBlock == nil {
				return fmt.Errorf("failed to decode certificate %v", arg)
			}
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				return err
			}
			key.Certificate = cert
		} else {
			return fmt.Errorf("unsupported file: %v", arg)
		}
	}

	return saveKey(key, filename)
}

func create(filename string, keyType kernel.KeyType) error {
	key := &kernel.Key{
		Type: keyType,
	}
	switch keyType {
	case kernel.KeyTypeAES, kernel.KeyTypeChaCha20:
		bits, err := keyType.BitSize()
		if err != nil {
			return err
		}
		key.Data = make([]byte, bits/8)
		_, err = rand.Read(key.Data)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("key type %v not supported", keyType)
	}

	return saveKey(key, filename)
}

func saveKey(key *kernel.Key, filename string) error {
	data, err := key.Bytes()
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)

	return err
}
