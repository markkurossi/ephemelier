//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"testing"
)

func TestSyscall(t *testing.T) {
	if SysExit != 1 {
		t.Errorf("SysExit=%v, expected 1", SysExit)
	}
	if SysGetrandom != 9 {
		t.Errorf("SysGetrandom=%v, expected 9", SysGetrandom)
	}
}
