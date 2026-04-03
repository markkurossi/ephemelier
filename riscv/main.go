//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"debug/elf"
	"flag"
	"fmt"
	"log"
)

func main() {
	flag.Parse()

	for _, arg := range flag.Args() {
		err := processFile(arg)
		if err != nil {
			log.Fatalf("failed to process %v: %v", arg, err)
		}
	}
}

func processFile(name string) error {
	f, err := elf.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()

	// Find .text section
	text := f.Section(".text")
	if text == nil {
		return fmt.Errorf(".text section not found")
	}

	data, err := text.Data()
	if err != nil {
		return err
	}

	fmt.Printf(".text at 0x%x, size %d bytes\n", text.Addr, len(data))

	pc := text.Addr

	decodeStream(data, pc)

	return nil
}
