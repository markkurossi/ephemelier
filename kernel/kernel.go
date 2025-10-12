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
	"github.com/markkurossi/go-libs/uuid"
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

// PID defines process ID.
type PID uint32

// G returns the garbler's PartyID from the pid.
func (pid PID) G() PartyID {
	return PartyID(pid >> 16 & 0xffff)
}

// E returns the evaluator's PartyID from the pid.
func (pid PID) E() PartyID {
	return PartyID(pid & 0xffff)
}

// SetG sets the garbler's PartyID to the pid.
func (pid *PID) SetG(id PartyID) {
	*pid = (*pid & 0xffff) | PID(id)<<16
}

// SetE sets the evaluator's PartyID to the pid.
func (pid *PID) SetE(id PartyID) {
	*pid = (*pid & 0xffff0000) | PID(id)
}

func (pid PID) String() string {
	return fmt.Sprintf("%d:%d", pid.G(), pid.E())
}

// PartyID is party's part of the PID.
type PartyID uint16

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
	NextPID     PartyID
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

		proc, err := kern.CreateProcess(p2p.NewConn(conn), RoleEvaluator,
			stdin.Copy(), stdout.Copy(), stderr.Copy())
		if err != nil {
			return err
		}
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
	proc, err := kern.CreateProcess(p2p.NewConn(mpc), RoleGarbler,
		stdin, stdout, stderr)
	if err != nil {
		mpc.Close()
		return nil, err
	}

	err = proc.SetProgram(prog)
	if err != nil {
		mpc.Close()
		return nil, err
	}

	// Send our uuid, pid, and program name.
	err = proc.conn.SendData(proc.uuid[:])
	if err != nil {
		mpc.Close()
		return nil, err
	}
	err = proc.conn.SendUint16(int(proc.pid.G()))
	if err != nil {
		mpc.Close()
		return nil, err
	}
	err = proc.conn.SendString(proc.prog.Filename)
	if err != nil {
		mpc.Close()
		return nil, err
	}
	err = proc.conn.Flush()
	if err != nil {
		mpc.Close()
		return nil, err
	}

	// Receive peer uuid and pid.
	peerUUID, err := proc.conn.ReceiveData()
	if err != nil {
		mpc.Close()
		return nil, err
	}
	_ = peerUUID
	eid, err := proc.conn.ReceiveUint16()
	if err != nil {
		mpc.Close()
		return nil, err
	}
	proc.pid.SetE(PartyID(eid))

	return proc, nil
}

// CreateProcess creates a new process.
func (kern *Kernel) CreateProcess(conn *p2p.Conn, role Role,
	stdin, stdout, stderr *FD) (*Process, error) {

	// XXX check wrapping
	kern.NextPID++
	if kern.NextPID == 0 {
		kern.NextPID++
	} else if kern.NextPID >= 0b1000000000000000 {
		kern.NextPID = 1
	}

	var pid PID
	if role == RoleGarbler {
		pid.SetG(kern.NextPID)
	} else {
		pid.SetE(kern.NextPID)
	}

	uid, err := uuid.New()
	if err != nil {
		return nil, err
	}

	proc := &Process{
		kern:    kern,
		role:    role,
		uuid:    uid,
		pid:     pid,
		conn:    conn,
		oti:     ot.NewCO(),
		iostats: p2p.NewIOStats(),
		fds:     make(map[int32]*FD),
	}

	proc.fds[0] = stdin
	proc.fds[1] = stdout
	proc.fds[2] = stderr

	return proc, nil
}
