//
// Copyright (c) 2025-2026 Markku Rossi
//
// All rights reserved.
//

// Package eef implements support for Ephemelier Executable Files (EEF).
package eef

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler/utils"
)

// Program defines EEF program.
type Program struct {
	Filename string
	Name     string
	Init     *Circuit
	Symtab   map[string]int
	ByName   map[string]*Circuit
	ByPC     map[int]*Circuit
	Missing  map[int]string
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
		Filename: file,
		Name:     path.Base(file),
		ByName:   make(map[string]*Circuit),
		ByPC:     make(map[int]*Circuit),
		Missing:  make(map[int]string),
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
				Name: MakeName(name),
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
				Name:  MakeName(name),
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
	// Report missing states.
	for name, id := range prog.Symtab {
		_, ok := prog.ByPC[id]
		if !ok {
			prog.Missing[id] = name
			fmt.Printf("warning: state %d (%s) not implemented\n", id, name)
		}
	}

	var pcs []int
	var maxNameLen int
	for pc, circ := range prog.ByPC {
		pcs = append(pcs, pc)
		if len(circ.Name) > maxNameLen {
			maxNameLen = len(circ.Name)
		}
	}
	sort.Ints(pcs)

	fmt.Printf("PC   State")
	for i := 5; i < maxNameLen; i++ {
		fmt.Print(" ")
	}
	fmt.Println("  Gates  Wires")
	fmt.Println("-----------------------------------------")

	for _, pc := range pcs {
		circ := prog.ByPC[pc]
		fmt.Printf("%-4d %s", pc, circ.Name)
		for i := len(circ.Name); i < maxNameLen; i++ {
			fmt.Print(" ")
		}
		if circ.Circ != nil {
			fmt.Printf(" %6d %6d", circ.Circ.NumGates, circ.Circ.NumWires)
		}
		fmt.Println()
	}
	if prog.Init == nil {
		return nil, fmt.Errorf("init undefined in program '%v'", file)
	}

	return prog, nil
}

// StateName returns the name of the state.
func (prog *Program) StateName(pc int) string {
	circ, ok := prog.ByPC[pc]
	if ok {
		return fmt.Sprintf("%d (%s)", pc, circ.Name)
	}
	name, ok := prog.Missing[pc]
	if ok {
		return fmt.Sprintf("%d (%s)", pc, name)
	}
	return fmt.Sprintf("state %d", pc)
}

// MakeName creates a state name from the file name.
func MakeName(name string) string {
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
