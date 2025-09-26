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

type Syscall uint8

func (call Syscall) String() string {
	name, ok := syscallNames[call]
	if ok {
		return name
	}
	return fmt.Sprintf("{Syscall %d}", call)
}

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

type Role int

const (
	RoleGarbler Role = iota
	RoleEvaluator
)

type Kernel struct {
	params *utils.Params
}

func New() *Kernel {
	return &Kernel{}
}

func (kern *Kernel) CreateProcess(conn *p2p.Conn, role Role) *Process {
	return &Process{
		kern: kern,
		role: role,
		conn: conn,
	}
}
