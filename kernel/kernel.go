//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/markkurossi/ephemelier/eef"
	"github.com/markkurossi/mpc/env"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

const (
	// KeySize specifies the system encryption key size.
	KeySize = 16

	// NonceSize specifies the encryption nonce sizes.
	NonceSize = 12

	// TagSize specifies the encryption authentication tag size.
	TagSize = 16
)

var (
	bo = binary.BigEndian
)

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
	TraceHex    bool
	Verbose     bool
	Diagnostics bool
	Port        string
	Stdin       *FD
	Stdout      *FD
	Stderr      *FD
	MPCConfig   *env.Config
}

// Kernel implements the Ephemelier kernel.
type Kernel struct {
	m            sync.Mutex
	params       Params
	nextPID      PartyID
	processes    map[PartyID]*Process
	processPorts map[PartyID]*Port
}

// New creates a new kernel.
func New(params *Params) *Kernel {
	kern := &Kernel{
		processes:    make(map[PartyID]*Process),
		processPorts: make(map[PartyID]*Port),
	}
	if params != nil {
		kern.params = *params
	}
	if kern.params.MPCConfig == nil {
		kern.params.MPCConfig = &env.Config{}
	}
	return kern
}

// Evaluator runs the evaluator with the stdio FDs.
func (kern *Kernel) Evaluator(stdin, stdout, stderr *FD) error {
	listener, err := net.Listen("tcp", kern.params.Port)
	if err != nil {
		return err
	}
	log.Printf("Listening for MPC connections at %s", kern.params.Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("New MPC connection from %s", conn.RemoteAddr())

		proc, err := kern.CreateProcess(p2p.NewConn(conn), RoleEvaluator, nil,
			stdin.Copy(), stdout.Copy(), stderr.Copy())
		if err != nil {
			return err
		}
		go proc.Run()
	}
}

// Spawn creates a new process for the file, arguments, and stdio FDs.
func (kern *Kernel) Spawn(file string, args []string,
	stdin, stdout, stderr *FD) (*Process, error) {

	prog, err := eef.NewProgram(file)
	if err != nil {
		return nil, err
	}

	// Connect to evaluator.
	mpc, err := net.Dial("tcp", kern.params.Port)
	if err != nil {
		return nil, err
	}
	proc, err := kern.CreateProcess(p2p.NewConn(mpc), RoleGarbler, args,
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

	// Send our pid and program name.
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

	// Receive peer pid.
	eid, err := proc.conn.ReceiveUint16()
	if err != nil {
		mpc.Close()
		return nil, err
	}
	proc.pid.SetE(PartyID(eid))

	return proc, nil
}

// CreateProcess creates a new process.
func (kern *Kernel) CreateProcess(conn *p2p.Conn, role Role, args []string,
	stdin, stdout, stderr *FD) (*Process, error) {

	rand := kern.params.MPCConfig.GetRandom()

	var key [KeySize]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	proc := &Process{
		kern:    kern,
		role:    role,
		args:    args,
		conn:    conn,
		oti:     ot.NewCO(rand),
		iostats: p2p.NewIOStats(),
		key:     key[:],
		fds:     make(map[int32]*FD),
	}
	proc.c = sync.NewCond(&proc.m)

	var pid PartyID

	kern.m.Lock()
	for {
		kern.nextPID++
		if kern.nextPID >= 0b1000000000000000 {
			kern.nextPID = 1
		}
		_, ok := kern.processes[kern.nextPID]
		if ok {
			continue
		}
		pid = kern.nextPID
		kern.processes[pid] = proc

		if role == RoleGarbler {
			proc.pid.SetG(pid)
		} else {
			proc.pid.SetE(pid)
		}
		break
	}
	kern.m.Unlock()

	err = kern.CreateProcessPort(pid, role)
	if err != nil {
		kern.RemoveProcess(pid)
		return nil, err
	}

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

	proc, ok := kern.processes[pid]
	return proc, ok
}

// RemoveProcess removes a process from the kernel.
func (kern *Kernel) RemoveProcess(pid PartyID) {
	kern.m.Lock()
	defer kern.m.Unlock()

	proc, ok := kern.processes[pid]
	if !ok {
		return
	}
	proc.SetState(SDEAD)
	delete(kern.processes, pid)
}

// CreateProcessPort creates the process port for the PartyID.
func (kern *Kernel) CreateProcessPort(pid PartyID, role Role) error {
	port, err := NewPort(role)
	if err != nil {
		return err
	}
	kern.m.Lock()
	defer kern.m.Unlock()

	_, ok := kern.processPorts[pid]
	if ok {
		return fmt.Errorf("process port already created: %v", pid)
	}
	kern.processPorts[pid] = port

	return nil
}

// GetProcessPort gets the process port for the PartyID.
func (kern *Kernel) GetProcessPort(pid PartyID) (*Port, error) {
	kern.m.Lock()
	defer kern.m.Unlock()

	port, ok := kern.processPorts[pid]
	if !ok {
		return nil, fmt.Errorf("invalid pid: %v", pid)
	}
	return port, nil
}
