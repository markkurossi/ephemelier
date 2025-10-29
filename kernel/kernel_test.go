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
	if SysGetpid != 17 {
		t.Errorf("SysGetpid=%v, expected 15", SysGetpid)
	}
	if SysGetport != 100 {
		t.Errorf("SysGetport=%v, expected 100", SysGetport)
	}
}

func TestPID(t *testing.T) {
	var pid PID

	var gid PartyID = 42
	var eid PartyID = 11

	pid.SetG(gid)
	pid.SetE(eid)

	if pid.G() != gid {
		t.Errorf("G: got %v, expected %v", pid.G(), gid)
	}
	if pid.E() != eid {
		t.Errorf("E: got %v, expected %v", pid.E(), eid)
	}
}
