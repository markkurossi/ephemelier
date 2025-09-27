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
	"path"

	"github.com/markkurossi/ephemelier/kernel"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var (
	params  *utils.Params
	oti     ot.OT
	mpcPort = ":9000"
	cmdPort = ":8080"
	states  = make(map[string]map[string][]byte)
	bo      = binary.BigEndian
	kern    = *kernel.New()
)

func main() {
	evaluator := flag.Bool("e", false, "evaluator / garbler mode")
	fVerbose := flag.Bool("v", false, "verbose output")
	fDiagnostics := flag.Bool("d", false, "diagnostics output")
	flag.Parse()

	log.SetFlags(0)

	params = utils.NewParams()
	defer params.Close()

	oti = ot.NewCO()

	params.Verbose = *fVerbose
	params.Diagnostics = *fDiagnostics
	params.OptPruneGates = true

	params.PkgPath = append(params.PkgPath,
		path.Join(os.Getenv("HOME"),
			"go/src/github.com/markkurossi/ephemelier/pkg"))

	fmt.Printf("PkgPath: %v\n", params.PkgPath)
	fmt.Printf("SymbolIDs: %v\n", params.SymbolIDs)

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
		for _, arg := range flag.Args() {
			err = garblerMode(arg)
			if err != nil {
				log.Fatal(err)
			}
		}
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

		proc := kern.CreateProcess(p2p.NewConn(conn), kernel.RoleEvaluator)
		go proc.Run()
	}
}

func garblerMode(file string) error {

	// Connect to evaluator.
	mpc, err := net.Dial("tcp", mpcPort)
	if err != nil {
		return err
	}
	defer mpc.Close()
	proc := kern.CreateProcess(p2p.NewConn(mpc), kernel.RoleGarbler)

	prog, err := kernel.NewProgram(file)
	if err != nil {
		return err
	}
	err = proc.SetProgram(prog)
	if err != nil {
		return err
	}

	return proc.Run()
}
