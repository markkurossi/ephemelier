//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"fmt"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// Errno defines error numbers.
type Errno int32

// Error numbers.
const (
	EBADF  Errno = 9
	EINVAL Errno = 22
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
	SysPeek
	SysRead
	SysSkip
	SysWrite
	SysOpen
	SysClose
	SysGetrandom
	SysYield
)

var syscallNames = map[Syscall]string{
	SysExit:      "exit",
	SysFork:      "fork",
	SysPeek:      "peek",
	SysRead:      "read",
	SysSkip:      "skip",
	SysWrite:     "write",
	SysOpen:      "open",
	SysClose:     "close",
	SysGetrandom: "getrandom",
	SysYield:     "yield",
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
	Params  Params
	NextPID int32
}

// New creates a new kernel.
func New(params *Params) *Kernel {
	kern := &Kernel{}
	if params != nil {
		kern.Params = *params
	}
	return kern
}

// CreateProcess creates a new process.
func (kern *Kernel) CreateProcess(conn *p2p.Conn, role Role,
	stdin, stdout, stderr *FD) *Process {

	kern.NextPID++

	proc := &Process{
		kern:    kern,
		role:    role,
		pid:     kern.NextPID,
		conn:    conn,
		oti:     ot.NewCO(),
		iostats: p2p.NewIOStats(),
		fds:     make(map[int32]*FD),
	}

	proc.fds[0] = stdin
	proc.fds[1] = stdout
	proc.fds[2] = stderr

	return proc
}
