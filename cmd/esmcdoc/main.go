//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/markkurossi/ephemelier/eef"
)

type transition struct {
	syscall string
	comment string
	target  string
}

var (
	reAssign    = regexp.MustCompile(`^\s*([a-zA-Z][a-zA-Z0-9]*)\s+:?=\s+intern\(([^)]+)\)`)
	reDefine    = regexp.MustCompile(`^\s*var\s+([a-zA-Z][a-zA-Z0-9]*)\s+[^\s]+\s+=\s+intern\(([^)]+)\)`)
	transitions = make(map[string][]*transition)
	nodes       = make(map[string]bool)
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	for _, file := range flag.Args() {
		err := processFile(file)
		if err != nil {
			log.Fatalf("failed to process file '%v': %v", file, err)
		}
	}
	out := os.Stdout

	fmt.Fprintf(out, `digraph circuit
{
  ranksep=.75;
  edge [fontname="Arial Narrow", fontsize=10];
  {
    node [shape=circle, fixedsize=true, fontname="Arial Narrow", fontsize=10];
`)
	for k := range nodes {
		fmt.Fprintf(out, "    %v\t[label=\"%v\"];\n", k, nodeName(k))
	}

	fmt.Fprintf(out, `  }
`)

	for k, v := range transitions {
		for _, t := range v {
			fmt.Fprintf(out, "  %v\t-> %v\t[label=\"%v\"];\n",
				k, t.target, t.syscall)
		}
	}
	fmt.Fprintf(out, `}
`)
}

func processFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	base := filepath.Base(file)

	this := eef.MakeName(base)
	nodes[this] = true

	vars := make(map[string][]string)

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return err
			}
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				return nil
			}
		}
		line = strings.TrimSpace(line)
		for strings.HasSuffix(line, ",") {
			next, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			next = strings.TrimSpace(next)
			line += " " + next
		}
		m := reAssign.FindStringSubmatch(line)
		if m == nil {
			m = reDefine.FindStringSubmatch(line)
		}
		if m != nil {
			vars[m[1]] = append(vars[m[1]], m[2])
		}

		if !strings.HasPrefix(line, "return ") {
			continue
		}
		args := splitLine(line[7:])
		if strings.HasPrefix(args[1], "intern(") {
			addTransition(this, args[1][7:len(args[1])-1], args[2][10:])
		} else {
			targets, ok := vars[args[1]]
			if ok {
				for _, target := range targets {
					addTransition(this, target, args[2][10:])
				}
			}
		}
	}
}

func addTransition(from, to, syscall string) {
	nodes[to] = true
	transitions[from] = append(transitions[from], &transition{
		syscall: syscall,
		target:  to,
	})
}

func splitLine(line string) []string {
	var result []string

	for i := 0; i < len(line); i++ {
		for ; i < len(line) && unicode.IsSpace(rune(line[i])); i++ {
		}
		if i >= len(line) {
			return result
		}

		start := i
		var nesting int
		for ; i < len(line) && (nesting > 0 || line[i] != ','); i++ {
			switch line[i] {
			case '(':
				nesting++
			case ')':
				nesting--
			}
		}
		result = append(result, line[start:i])
	}
	return result
}

func nodeName(node string) string {
	node = strings.TrimPrefix(node, "St")

	var result string
	for len(node) > 0 {
		var i int
		for i = 1; i < len(node) && unicode.IsLower(rune(node[i])); i++ {
		}
		if len(result) > 0 {
			result += "\\n"
		}
		result += node[:i]
		node = node[i:]
	}
	return result
}
