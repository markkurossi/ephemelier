//
// Copyright (c) 2023-2025 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/markkurossi/ephemelier/kernel"
)

var (
	mpcPort     = ":9000"
	consolePort = ":2323"
	bo          = binary.BigEndian
	kern        *kernel.Kernel
	stdin       = kernel.NewFileFD(os.Stdin)
	stdout      = kernel.NewFileFD(os.Stdout)
	stderr      = kernel.NewFileFD(os.Stderr)
	devNull     = kernel.NewDevNullFD()
)

func main() {
	evaluator := flag.Bool("e", false, "evaluator / garbler mode")
	fVerbose := flag.Bool("v", false, "verbose output")
	fDiagnostics := flag.Bool("d", false, "diagnostics output")
	fConsole := flag.Bool("console", false, "start console")
	ktrace := flag.Bool("ktrace", false, "kernel trace")
	flag.Parse()

	log.SetFlags(0)

	kern = kernel.New(&kernel.Params{
		Trace:       *ktrace,
		Verbose:     *fVerbose,
		Diagnostics: *fDiagnostics,
		Port:        mpcPort,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
	})

	mode := "Garbler"
	if *evaluator {
		mode = "Evaluator"
	}

	fmt.Printf("Ephemelier %v Node\n", mode)

	var err error
	if *evaluator {
		err = kern.Evaluator(devNull, devNull, stderr)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	// Run all programs as Garbler.

	var wg sync.WaitGroup
	for _, arg := range flag.Args() {
		proc, err := kern.Spawn(arg, nil, stdin.Copy(), stdout.Copy(),
			stderr.Copy())
		if err != nil {
			log.Print(err)
			continue
		}
		wg.Go(func() {
			err := proc.Run()
			if err != nil {
				log.Print(err)
			}
		})
	}

	// Start console.
	if *fConsole {
		err = console(&wg)
		if err != nil {
			log.Print(err)
		}
	}

	// Wait for all programs to terminate.
	wg.Wait()
}

func console(wg *sync.WaitGroup) error {
	// Create command listener.
	listener, err := net.Listen("tcp", consolePort)
	if err != nil {
		return err
	}
	log.Printf("Console running at %s", consolePort)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("New console connection from %s", conn.RemoteAddr())
		fd := kernel.NewSocketFD(conn)
		proc, err := kern.Spawn("bin/sh", nil, fd, fd.Copy(), fd.Copy())
		if err != nil {
			return err
		}
		wg.Go(func() {
			err := proc.Run()
			conn.Close()
			if err != nil {
				log.Print(err)
			}
		})
	}
}
