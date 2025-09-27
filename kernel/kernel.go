//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"fmt"

	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/p2p"
)

// Syscall defines system calls.
type Syscall uint8

func (call Syscall) String() string {
	name, ok := syscallNames[call]
	if ok {
		return name
	}
	return fmt.Sprintf("{Syscall %d}", call)
}

// System calls.
const (
	SysExit Syscall = iota + 1
	SysFork
	SysRead
	SysWrite
	SysOpen
	SysClose
	SysGetrandom
)

var syscallNames = map[Syscall]string{
	SysExit:      "exit",
	SysFork:      "fork",
	SysRead:      "read",
	SysWrite:     "write",
	SysOpen:      "open",
	SysClose:     "close",
	SysGetrandom: "getrandom",
}

// Role defines the process roles.
type Role int

// Process roles.
const (
	RoleGarbler Role = iota
	RoleEvaluator
)

// Kernel implements the Ephemelier kernel.
type Kernel struct {
	params *utils.Params
}

// New creates a new kernel.
func New() *Kernel {
	return &Kernel{}
}

// CreateProcess creates a new process.
func (kern *Kernel) CreateProcess(conn *p2p.Conn, role Role) *Process {
	return &Process{
		kern: kern,
		role: role,
		conn: conn,
	}
}
