//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"fmt"
	"log"
	"net"

	"github.com/markkurossi/ephemelier/eef"
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
	SysSpawn
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
	SysSpawn:     "spawn",
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

// Params define kernel parameters.
type Params struct {
	Trace       bool
	Verbose     bool
	Diagnostics bool
	Port        string
	Stdin       *FD
	Stdout      *FD
	Stderr      *FD
}

// Kernel implements the Ephemelier kernel.
type Kernel struct {
	Params      Params
	NextPID     uint32
	ProcessByID map[[16]byte]*Process
}

// New creates a new kernel.
func New(params *Params) *Kernel {
	kern := &Kernel{
		ProcessByID: make(map[[16]byte]*Process),
	}
	if params != nil {
		kern.Params = *params
	}
	return kern
}

// Evaluator runs the evaluator with the stdio FDs.
func (kern *Kernel) Evaluator(stdin, stdout, stderr *FD) error {
	listener, err := net.Listen("tcp", kern.Params.Port)
	if err != nil {
		return err
	}
	log.Printf("Listening for MPC connections at %s", kern.Params.Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("New MPC connection from %s", conn.RemoteAddr())

		proc := kern.CreateProcess(p2p.NewConn(conn), RoleEvaluator,
			stdin.Copy(), stdout.Copy(), stderr.Copy())
		go proc.Run()
	}
}

// Spawn creates a new process for the file and stdio FDs.
func (kern *Kernel) Spawn(file string, stdin, stdout, stderr *FD) (
	*Process, error) {

	prog, err := eef.NewProgram(file)
	if err != nil {
		return nil, err
	}

	// Connect to evaluator.
	mpc, err := net.Dial("tcp", kern.Params.Port)
	if err != nil {
		return nil, err
	}
	proc := kern.CreateProcess(p2p.NewConn(mpc), RoleGarbler,
		stdin, stdout, stderr)

	err = proc.SetProgram(prog)
	if err != nil {
		mpc.Close()
		return nil, err
	}

	return proc, nil
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
