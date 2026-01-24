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
	"strings"

	"github.com/markkurossi/ephemelier/kernel"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	bo = binary.BigEndian
)

func main() {
	vault := flag.String("vault", "", "vault prefix")
	fs := flag.String("fs", "", "filesystem directory")
	key := flag.String("key", "", "filesystem encryption key")
	prefix := flag.String("prefix", "", "source/destination file prefix")
	bs := flag.Int("bs", 1024, "block size")
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
		err := importFiles(*vault, *fs, *key, *prefix, *bs, flag.Args()[1:])
		if err != nil {
			log.Fatalf("could not import files: %s", err)
		}
	case "export":
		err := exportFiles(*vault, *fs, *key, flag.Args()[1:])
		if err != nil {
			log.Fatalf("could not export files: %s", err)
		}
	case "stat":
		err := statFiles(*vault, *fs, *key, flag.Args()[1:])
		if err != nil {
			log.Fatalf("could not export files: %s", err)
		}
	default:
		log.Fatalf("invalid command: %s", flag.Args()[0])
	}
}

func importFiles(vault, fs, keyname, prefix string, blockSize int,
	files []string) error {

	key, err := makeKey(vault, keyname)
	if err != nil {
		return err
	}

	for _, file := range files {
		err := encryptFile(fs, file, prefix, key, blockSize)
		if err != nil {
			return err
		}
	}

	return nil
}

func encryptFile(fs, file, prefix string, key []byte, blockSize int) error {
	if blockSize <= chacha20poly1305.Overhead {
		return fmt.Errorf("bock sizes must be bigger than cipher overhead %v",
			chacha20poly1305.Overhead)
	}
	buf := make([]byte, blockSize)

	// Make sure the directory exists.
	if !strings.HasPrefix(file, prefix) {
		return fmt.Errorf("input file %v does not have prefix %v",
			file, prefix)
	}

	dst := filepath.Join(fs, file[len(prefix):])
	err := os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		return err
	}

	// Create file header.

	fi, err := os.Stat(file)
	if err != nil {
		return err
	}

	hdr := &kernel.FileHeader{
		Magic:     kernel.EncrFileMagic,
		BlockSize: uint16(blockSize),
		Algorithm: kernel.KeyTypeChaCha20,
		PlainSize: fi.Size(),
	}
	_, err = rand.Read(hdr.Nonce[:])
	if err != nil {
		return err
	}

	var aad [14]byte
	bo.PutUint64(aad[4:], uint64(hdr.PlainSize))
	bo.PutUint16(aad[:12], uint16(hdr.Flags))

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(hdr.Bytes())
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
		n, err := in.Read(buf[:blockSize-chacha20poly1305.Overhead])
		if n == 0 {
			break
		}
		if err != nil {
			return err
		}

		// Create nonce.

		var nonce [12]byte
		copy(nonce[:], hdr.Nonce[:])
		var seq [8]byte

		bo.PutUint64(seq[:], uint64(i))
		for i := 0; i < len(seq); i++ {
			nonce[4+i] ^= seq[i]
		}

		// Update AAD.
		bo.PutUint32(aad[0:], uint32(i))

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

	var hdrbuf [kernel.EncrFileHdrSize]byte
	_, err = in.Read(hdrbuf[:])
	if err != nil {
		return err
	}
	hdr, err := kernel.NewFileHeader(hdrbuf[:])
	if err != nil {
		return err
	}
	// XXX check KeyType

	buf := make([]byte, hdr.BlockSize)

	var aad [14]byte
	bo.PutUint64(aad[4:], uint64(hdr.PlainSize))
	bo.PutUint16(aad[:12], uint16(hdr.Flags))

	dst := filepath.Join("x", file)
	err = os.MkdirAll(filepath.Dir(dst), 0755)
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
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
		copy(nonce[:], hdr.Nonce[:])
		var seq [8]byte
		bo.PutUint64(seq[:], uint64(i))
		for i := 0; i < len(seq); i++ {
			nonce[4+i] ^= seq[i]
		}

		bo.PutUint32(aad[0:], uint32(i))

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

func statFiles(vault, fs, keyname string, files []string) error {
	key, err := makeKey(vault, keyname)
	if err != nil {
		return err
	}

	for _, file := range files {
		err := statFile(fs, file, key)
		if err != nil {
			return err
		}
	}

	return nil
}

func statFile(fs, file string, key []byte) error {
	// Open input file and read file header.
	src := filepath.Join(fs, file)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	var hdrbuf [kernel.EncrFileHdrSize]byte
	_, err = in.Read(hdrbuf[:])
	if err != nil {
		return err
	}
	hdr, err := kernel.NewFileHeader(hdrbuf[:])
	if err != nil {
		return err
	}

	fmt.Printf("file %v:\n", file)
	fmt.Printf(" - magic    : %08x\n", hdr.Magic)
	fmt.Printf(" - blockSize: %v\n", hdr.BlockSize)
	fmt.Printf(" - algorithm: %v\n", hdr.Algorithm)
	fmt.Printf(" - flags    : %04x\n", hdr.Flags)
	fmt.Printf(" - plainSize: %v\n", hdr.PlainSize)
	fmt.Printf(" - nonce    : %x\n", hdr.Nonce)

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
