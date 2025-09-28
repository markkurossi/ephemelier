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

	"github.com/markkurossi/ephemelier/eef"
	"github.com/markkurossi/ephemelier/kernel"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var (
	oti         ot.OT
	mpcPort     = ":9000"
	consolePort = ":2323"
	bo          = binary.BigEndian
	kern        *kernel.Kernel
	stdin       = kernel.NewFileFD(os.Stdin)
	stdout      = kernel.NewFileFD(os.Stdout)
	stderr      = kernel.NewFileFD(os.Stderr)
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
	})

	oti = ot.NewCO()

	mode := "Garbler"
	if *evaluator {
		mode = "Evaluator"
	}

	fmt.Printf("Ephemelier %v Node\n", mode)

	var err error
	if *evaluator {
		err = evaluatorMode()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Run all programs.

		var wg sync.WaitGroup
		for _, arg := range flag.Args() {
			wg.Go(func() {
				err = garblerMode(arg, stdin.Copy(), stdout.Copy(),
					stderr.Copy())
				if err != nil {
					log.Print(err)
				}
			})
		}

		// Start console.
		if *fConsole {
			err = console()
			if err != nil {
				log.Print(err)
			}
		}

		// Wait for all programs to terminate.
		wg.Wait()
	}
}

func evaluatorMode() error {
	listener, err := net.Listen("tcp", mpcPort)
	if err != nil {
		return err
	}
	log.Printf("Listening for MPC connections at %s", mpcPort)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("New MPC connection from %s", conn.RemoteAddr())

		proc := kern.CreateProcess(p2p.NewConn(conn), kernel.RoleEvaluator,
			stdin.Copy(), stdout.Copy(), stderr.Copy())
		go proc.Run()
	}
}

func garblerMode(file string, stdin, stdout, stderr *kernel.FD) error {
	// Connect to evaluator.
	mpc, err := net.Dial("tcp", mpcPort)
	if err != nil {
		return err
	}
	defer mpc.Close()
	proc := kern.CreateProcess(p2p.NewConn(mpc), kernel.RoleGarbler,
		stdin, stdout, stderr)

	prog, err := eef.NewProgram(file)
	if err != nil {
		return err
	}
	err = proc.SetProgram(prog)
	if err != nil {
		return err
	}

	return proc.Run()
}

func console() error {
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
		err = garblerMode("examples/hello", fd, fd.Copy(), fd.Copy())
		if err != nil {
			return err
		}
	}
}
