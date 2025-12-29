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
	"runtime/pprof"
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
	ktraceHex := flag.Bool("x", false, "hexdump ktrace data fields")
	fs := flag.String("fs", "", "filesystem root directory")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")
	memprofile := flag.String("memprofile", "",
		"write memory profile to `file`")
	flag.Parse()

	log.SetFlags(0)

	if len(*cpuprofile) > 0 {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	params := &kernel.Params{
		Trace:       *ktrace,
		TraceHex:    *ktraceHex,
		Verbose:     *fVerbose,
		Diagnostics: *fDiagnostics,
		Filesystem:  *fs,
		Port:        mpcPort,
		Stdin:       stdin,
		Stdout:      stdout,
		Stderr:      stderr,
	}
	if len(params.Filesystem) == 0 {
		if *evaluator {
			params.Filesystem = "data/fs1"
		} else {
			params.Filesystem = "data/fs0"
		}
	}
	// Make sure filesystem root exists.
	err := os.MkdirAll(params.Filesystem, 0755)
	if err != nil {
		log.Fatalf("could not create filesystem root '%s': %s",
			params.Filesystem, err)
	}

	kern = kernel.New(params)

	mode := "Garbler"
	if *evaluator {
		mode = "Evaluator"
	}

	fmt.Printf("Ephemelier %v Node\n", mode)

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

	if len(*memprofile) > 0 {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal("could not create memory profile: ", err)
		}
		defer f.Close()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
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
