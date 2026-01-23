//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

// The fs-tool is an utility program to encrypt and import files to
// the filesystem. It assumes the filesystem and vault locations are
// readable. If the locations are different (or on different
// machines), you must write an Ephemelier program to do the proper
// MPC import.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/markkurossi/ephemelier/kernel"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FileMagic = uint16(0x4501)
	BlockSize = 1024
)

var (
	bo = binary.BigEndian
)

func main() {
	vault := flag.String("vault", "", "vault prefix")
	fs := flag.String("fs", "", "filesystem directory")
	key := flag.String("key", "", "filesystem encryption key")
	flag.Parse()

	if len(*vault) == 0 {
		log.Fatalf("vault prefix not specified")
	}
	if len(*fs) == 0 {
		log.Fatalf("filesystem directory unspecified")
	}
	if len(*key) == 0 {
		log.Fatal("filesystem encryption key unspecified")
	}

	if len(flag.Args()) == 0 {
		log.Fatalf("usage: fs-tool import/export filename...")
	}

	switch flag.Args()[0] {
	case "import":
		err := importFiles(*vault, *fs, *key, flag.Args()[1:])
		if err != nil {
			log.Fatalf("could not import files: %s", err)
		}
	case "export":
		err := exportFiles(*vault, *fs, *key, flag.Args()[1:])
		if err != nil {
			log.Fatalf("could not export files: %s", err)
		}
	default:
		log.Fatalf("invalid command: %s", flag.Args()[0])
	}
}

func importFiles(vault, fs, keyname string, files []string) error {
	key, err := makeKey(vault, keyname)
	if err != nil {
		return err
	}

	for _, file := range files {
		err := encryptFile(fs, file, key)
		if err != nil {
			return err
		}
	}

	return nil
}

func makeKey(vault, keyname string) ([]byte, error) {
	path := filepath.Join(fmt.Sprintf("%s0", vault), keyname)
	gkey, err := kernel.OpenKey(path)
	if err != nil {
		return nil, err
	}
	path = filepath.Join(fmt.Sprintf("%s1", vault), keyname)
	ekey, err := kernel.OpenKey(path)
	if err != nil {
		return nil, err
	}
	gdata := make([]byte, 512)
	gn := gkey.Read(gdata)
	if gn <= 0 {
		return nil, fmt.Errorf("failed to read gkey: %v", kernel.Errno(-gn))
	}
	edata := make([]byte, 512)
	en := ekey.Read(edata)
	if en != gn {
		return nil, fmt.Errorf("invalid ekey: read %v, expected %v", en, gn)
	}

	for i := 0; i < gn; i++ {
		gdata[i] ^= edata[i]
	}
	return gdata[:gn], nil
}

func encryptFile(fs, file string, key []byte) error {
	buf := make([]byte, BlockSize)

	// Make sure the directory exists.
	dst := filepath.Join(fs, file)
	err := os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		return err
	}

	// Create file header.

	fi, err := os.Stat(file)
	if err != nil {
		return err
	}

	var flags uint16

	var hdr [28]byte
	bo.PutUint16(hdr[0:], FileMagic)
	bo.PutUint16(hdr[2:], uint16(kernel.KeyTypeChaCha20))
	bo.PutUint16(hdr[4:], BlockSize)
	bo.PutUint16(hdr[6:], flags)
	bo.PutUint64(hdr[8:], uint64(fi.Size()))

	var aad [14]byte
	bo.PutUint64(aad[4:], uint64(fi.Size()))
	bo.PutUint16(aad[:12], flags)

	_, err = rand.Read(hdr[16:28])
	if err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(hdr[:])
	if err != nil {
		return err
	}

	in, err := os.Open(file)
	if err != nil {
		return err
	}
	defer in.Close()

	// Encrypt blocks.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	for i := 0; ; i++ {
		n, err := in.Read(buf[:BlockSize-chacha20poly1305.Overhead])
		if n == 0 {
			break
		}
		if err != nil {
			return err
		}

		var nonce [12]byte
		copy(nonce[:], hdr[16:])
		var seq [8]byte
		bo.PutUint64(seq[:], uint64(i))
		for i := 0; i < len(seq); i++ {
			nonce[4+i] ^= seq[i]
		}

		cipher := aead.Seal(buf[:0], nonce[:], buf[:n], aad[:])
		_, err = out.Write(cipher)
		if err != nil {
			return err
		}
	}

	return nil
}

func exportFiles(vault, fs, keyname string, files []string) error {
	key, err := makeKey(vault, keyname)
	if err != nil {
		return err
	}

	for _, file := range files {
		err := decryptFile(fs, file, key)
		if err != nil {
			return err
		}
	}

	return nil
}

func decryptFile(fs, file string, key []byte) error {
	// Open input file and read file header.
	src := filepath.Join(fs, file)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	var hdr [28]byte
	_, err = in.Read(hdr[:])
	if err != nil {
		return err
	}
	magic := bo.Uint16(hdr[0:])
	if magic != FileMagic {
		return fmt.Errorf("invalid magic: %04x", magic)
	}
	// XXX check KeyType
	blockSize := int(bo.Uint16(hdr[4:]))
	flags := bo.Uint16(hdr[6:])
	fileSize := bo.Uint64(hdr[8:])

	buf := make([]byte, blockSize)

	var aad [14]byte
	bo.PutUint64(aad[4:], fileSize)
	bo.PutUint16(aad[:12], flags)

	out, err := os.Create(filepath.Join("x", file))
	if err != nil {
		return err
	}
	defer out.Close()

	// Decrypt blocks.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	for i := 0; ; i++ {
		n, err := in.Read(buf[:])
		if n == 0 {
			break
		}
		if err != nil {
			return err
		}

		var nonce [12]byte
		copy(nonce[:], hdr[16:])
		var seq [8]byte
		bo.PutUint64(seq[:], uint64(i))
		for i := 0; i < len(seq); i++ {
			nonce[4+i] ^= seq[i]
		}

		plain, err := aead.Open(buf[:0], nonce[:], buf[:n], aad[:])
		if err != nil {
			return err
		}
		_, err = out.Write(plain)
		if err != nil {
			return err
		}
	}

	return nil
}
