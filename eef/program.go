//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

// Package eef implements support for Ephemelier Executable Files (EEF).
package eef

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler/utils"
)

// Program defines EEF program.
type Program struct {
	Name   string
	Init   *Circuit
	Symtab map[string]int
	ByName map[string]*Circuit
	ByPC   map[int]*Circuit
}

// Circuit implements a program state.
type Circuit struct {
	Name  string
	PC    int
	Circ  *circuit.Circuit
	DMPCL []byte
}

// NewProgram parses the EEF file.
func NewProgram(file string) (*Program, error) {
	entries, err := os.ReadDir(file)
	if err != nil {
		return nil, err
	}
	prog := &Program{
		Name:   file,
		ByName: make(map[string]*Circuit),
		ByPC:   make(map[int]*Circuit),
	}

	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(file, name)

		if name == "symtab" {
			params := utils.NewParams()
			err = params.LoadSymbolIDs(path)
			if err != nil {
				return nil, err
			}
			prog.Symtab = params.SymbolIDs
		} else if circuit.IsFilename(name) {
			c, err := circuit.Parse(path)
			if err != nil {
				return nil, err
			}
			circ := &Circuit{
				Name: makeName(name),
				Circ: c,
			}

			prog.ByName[circ.Name] = circ
		} else if strings.HasSuffix(name, ".dmpcl") {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				return nil, err
			}
			dmpcl := &Circuit{
				Name:  makeName(name),
				DMPCL: data,
			}
			prog.ByName[dmpcl.Name] = dmpcl
		}
	}

	// Create mappings from PC to circuit.
	for name, circ := range prog.ByName {
		id, ok := prog.Symtab[name]
		if !ok {
			return nil, fmt.Errorf("symbol %v undefined in PC map", name)
		}
		circ.PC = id
		prog.ByPC[id] = circ

		if name == "Init" {
			prog.Init = circ
		}
	}
	for pc, circ := range prog.ByPC {
		fmt.Printf("%-4d %-16s", pc, circ.Name)

		if circ.Circ != nil {
			fmt.Printf("\t#gates=%-5d #wires=%v\n",
				circ.Circ.NumGates, circ.Circ.NumWires)
		}
	}
	if prog.Init == nil {
		return nil, fmt.Errorf("init undefined in program '%v'", file)
	}

	return prog, nil
}

func makeName(name string) string {
	idx := strings.IndexByte(name, '.')
	if idx >= 0 {
		name = name[:idx]
	}
	var result string

	if name != "init" {
		result = "St"
	}

	parts := strings.Split(name, "_")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		result += strings.ToUpper(part[:1])
		result += strings.ToLower(part[1:])
	}
	return result
}
