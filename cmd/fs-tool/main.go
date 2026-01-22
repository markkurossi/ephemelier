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
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"github.com/markkurossi/ephemelier/kernel"
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
	default:
		log.Fatalf("invalid command: %s", flag.Args()[0])
	}
}

func importFiles(vault, fs, keyname string, files []string) error {
	path := filepath.Join(fmt.Sprintf("%s0", vault), keyname)
	gkey, err := kernel.OpenKey(path)
	if err != nil {
		return err
	}
	path = filepath.Join(fmt.Sprintf("%s1", vault), keyname)
	ekey, err := kernel.OpenKey(path)
	if err != nil {
		return err
	}
	gdata := make([]byte, 512)
	gn := gkey.Read(gdata)
	if gn <= 0 {
		return fmt.Errorf("failed to read gkey: %v", kernel.Errno(-gn))
	}
	edata := make([]byte, 512)
	en := ekey.Read(edata)
	if en != gn {
		return fmt.Errorf("invalid ekey: read %v, expected %v", en, gn)
	}

	for i := 0; i < gn; i++ {
		gdata[i] ^= edata[i]
	}
	key := gdata[:gn]

	fmt.Printf("key: %x\n", key)

	return fmt.Errorf("importFiles not implemented yet")
}
