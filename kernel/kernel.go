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
	"sync"

	"github.com/markkurossi/ephemelier/eef"
	"github.com/markkurossi/go-libs/uuid"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// Errno defines error numbers.
type Errno int32

// Error numbers.
const (
	ENOENT Errno = 2
	EBADF  Errno = 9
	ECHILD Errno = 10
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
	SysWait
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
	SysWait:      "wait",
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
	m         sync.Mutex
	Params    Params
	NextPID   PartyID
	Processes map[PartyID]*Process
}

// New creates a new kernel.
func New(params *Params) *Kernel {
	kern := &Kernel{
		Processes: make(map[PartyID]*Process),
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

	uid, err := uuid.New()
	if err != nil {
		return nil, err
	}

	proc := &Process{
		kern:    kern,
		role:    role,
		uuid:    uid,
		conn:    conn,
		oti:     ot.NewCO(),
		iostats: p2p.NewIOStats(),
		fds:     make(map[int32]*FD),
	}
	proc.c = sync.NewCond(&proc.m)

	kern.m.Lock()
	for {
		kern.NextPID++
		if kern.NextPID >= 0b1000000000000000 {
			kern.NextPID = 1
		}
		_, ok := kern.Processes[kern.NextPID]
		if ok {
			continue
		}
		kern.Processes[kern.NextPID] = proc

		if role == RoleGarbler {
			proc.pid.SetG(kern.NextPID)
		} else {
			proc.pid.SetE(kern.NextPID)
		}
		break
	}
	kern.m.Unlock()

	proc.SetState(SIDL)

	proc.fds[0] = stdin
	proc.fds[1] = stdout
	proc.fds[2] = stderr

	return proc, nil
}

// GetProcess gets a process by its PartyID.
func (kern *Kernel) GetProcess(pid PartyID) (*Process, bool) {
	kern.m.Lock()
	defer kern.m.Unlock()

	proc, ok := kern.Processes[pid]
	return proc, ok
}

// RemoveProcess removes a process from the kernel.
func (kern *Kernel) RemoveProcess(pid PartyID) {
	kern.m.Lock()
	defer kern.m.Unlock()

	proc, ok := kern.Processes[pid]
	if !ok {
		return
	}
	proc.SetState(SDEAD)
	delete(kern.Processes, pid)
}
