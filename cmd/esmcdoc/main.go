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
	"math"
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
  edge [fontname="Arial Narrow", fontsize=10];
  {
    node [
      shape=doublecircle,
      fixedsize=true,
      fontname="Arial Narrow",
      fontsize=10
    ];
    Init [label="init"];
  }
  {
    node [
      shape=circle,
      fixedsize=true,
      fontname="Arial Narrow",
      fontsize=10
    ];
`)
	for k := range nodes {
		if k == "Init" {
			continue
		}
		fmt.Fprintf(out, "    %v\t[label=%q];\n", k, nodeName(k))
	}

	fmt.Fprintf(out, `  }
`)

	for k, v := range transitions {
		for _, t := range v {
			fmt.Fprintf(out, "  %v\t-> %v\t[label=\"%v\"];\n",
				k, t.target, strings.ToLower(t.syscall))
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
	parts := nodeNameSplit(node)
	name, _ := layout(parts)
	return name
}

func nodeNameSplit(node string) []string {
	node = strings.TrimPrefix(node, "St")

	var result []string
	for len(node) > 0 {
		var i int
		for i = 1; i < len(node) && unicode.IsLower(rune(node[i])); i++ {
		}
		result = append(result, strings.ToLower(node[:i]))
		node = node[i:]
	}
	return result
}

type layouter struct {
	best        []string
	bestBadness int
}

var sizes = [][]int{
	[]int{0},
	[]int{
		3552, // nnnnnnnn - 8xn (8*444)
	},
	[]int{
		3108, // nnnnnnn - 7xn (7*444)
		3108, // nnnnnnn - 7xn (7*444)
	},
	[]int{
		2664, //  nnnnnn  - 6xn (6*444)
		3387, // nnnnnnnn - 8xn (8*444)
		2664, //  nnnnnn  - 6xn (6*444)
	},
	[]int{
		1332, //   nnn   - 3Xn (3*444)
		3108, // nnnnnnn - 7xn (7*444)
		3108, // nnnnnnn - 7xn (7*444)
		1332, //   nnn   - 3Xn (3*444)
	},
}

func layout(parts []string) (string, int) {
	ctx := &layouter{
		bestBadness: math.MaxInt,
	}
	ctx.iter(parts, nil)

	return strings.Join(ctx.best, "\n"), ctx.bestBadness
}

func (layouter *layouter) iter(parts, result []string) {
	if len(parts) == 0 {
		var badness int
		var layout []string

		if len(result) > 4 {
			var overhead int
			if len(result)%2 == 0 {
				overhead = (len(result) - 4) / 2
				layout = result[overhead : overhead+4]
			} else {
				overhead = (len(result) - 3) / 2
				layout = result[overhead : overhead+3]
			}
			for i := 0; i < overhead; i++ {
				badness += width(result[i])
				badness += width(result[len(result)-1-i])
			}
		} else {
			layout = result
		}
		limits := sizes[len(layout)]
		for i, l := range layout {
			w := width(l)
			if w > limits[i] {
				badness += w - limits[i]
			}
		}
		if badness < layouter.bestBadness {
			layouter.bestBadness = badness
			layouter.best = layout
		}

		return
	}

	var first string

	for i := 0; i < len(parts); i++ {
		if i > 0 {
			first += " "
		}
		first += parts[i]
		layouter.iter(parts[i+1:], append(result, first))
	}
}

func width(string string) int {
	var result int
	for _, r := range string {
		result += charWidths[r]
	}
	return result
}
