//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"testing"
)

func TestAssign(t *testing.T) {
	lines := []string{
		`		state = intern(StTlsserverKexFinished)`,
		`		state := intern(StTlsserverKexFinished)`,
		`	var state kernel.PC = intern(StTlsserverKex)`,
	}

	for idx, line := range lines {
		m := reAssign.FindStringSubmatch(line)
		if m != nil {
			t.Logf("%v = %v\n", m[1], m[2])
			continue
		}
		m = reDefine.FindStringSubmatch(line)
		if m != nil {
			t.Logf("%v = %v\n", m[1], m[2])
			continue
		}
		t.Errorf("line %d not matching\n", idx)
	}
}
