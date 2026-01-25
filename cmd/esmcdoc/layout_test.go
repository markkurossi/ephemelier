//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"fmt"
	"testing"
)

var layoutTests = []string{
	"StHttpdCtPlainOpen",
}

func TestLayout(t *testing.T) {
	for idx, test := range layoutTests {
		parts := nodeNameSplit(test)
		name, badness := layout(parts)

		fmt.Printf("test-%d: %q => %q\t%v\n", idx, test, name, badness)
	}
}
