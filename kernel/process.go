//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/markkurossi/ephemelier/eef"
	"github.com/markkurossi/go-libs/uuid"
	"github.com/markkurossi/mpc"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// Process defines a kernel process.
type Process struct {
	m           sync.Mutex
	c           *sync.Cond
	kern        *Kernel
	role        Role
	uuid        uuid.UUID
	pid         PID
	conn        *p2p.Conn
	oti         ot.OT
	state       ProcState
	iostats     p2p.IOStats
	prog        *eef.Program
	mpclcParams *utils.Params
	key         []byte
	mem         []byte
	pc          uint16
	fds         map[int32]*FD
	exitVal     int32
}

// ProcState defines process states.
type ProcState int

// Process states.
const (
	SIDL ProcState = iota
	SRUN
	SSLEEP
	SSTOP
	SZOMB
	SDEAD
)

var stateNames = map[ProcState]string{
	SIDL:   "idl",
	SRUN:   "run",
	SSLEEP: "sleep",
	SSTOP:  "stop",
	SZOMB:  "zomb",
	SDEAD:  "dead",
}

func (st ProcState) String() string {
	name, ok := stateNames[st]
	if ok {
		return name
	}
	return fmt.Sprintf("{ProcState %d}", st)
}

// Stats provides process statistics.
type Stats struct {
	MPCD      time.Duration
	NumGates  uint64
	NumWires  uint64
	NumXOR    uint64
	NumNonXOR uint64
}

func (stats Stats) String() string {
	return fmt.Sprintf("g=%v,xor=%v,nxor=%v,d=%v",
		stats.NumGates, stats.NumXOR, stats.NumNonXOR, stats.MPCD)
}

func (proc *Process) diagnostics() bool {
	return proc.kern.Params.Diagnostics
}

func (proc *Process) verbose() bool {
	return proc.kern.Params.Verbose
}

// SetState sets the process state.
func (proc *Process) SetState(st ProcState) {
	proc.m.Lock()
	proc.state = st
	proc.m.Unlock()
	proc.c.Broadcast()
}

// WaitState waits until the process reaches the specified state.
func (proc *Process) WaitState(st ProcState) {
	proc.m.Lock()
	for proc.state < st {
		proc.c.Wait()
	}
	proc.m.Unlock()
}

// SetProgram sets the program for the process.
func (proc *Process) SetProgram(prog *eef.Program) error {
	var key [16]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return err
	}
	proc.prog = prog
	proc.key = key[:]

	proc.mpclcParams = utils.NewParams()
	proc.mpclcParams.Verbose = proc.verbose()
	proc.mpclcParams.Diagnostics = proc.diagnostics()
	proc.mpclcParams.MPCLCErrorLoc = true
	proc.mpclcParams.PkgPath = []string{
		"../../pkg",
	}
	proc.mpclcParams.SymbolIDs = prog.Symtab

	proc.mpclcParams.Warn.ReturnDiff = false
	proc.mpclcParams.Warn.Unreachable = false

	return nil
}

// Run runs the process.
func (proc *Process) Run() (err error) {
	defer proc.conn.Close()

	proc.SetState(SRUN)

	fmt.Printf("Process.Run\n")
	switch proc.role {
	case RoleGarbler:
		err = proc.runGarbler()
	case RoleEvaluator:
		err = proc.runEvaluator()
	}
	if err != nil {
		log.Printf("process error: %v", err)
	}
	// Close all FDs.
	for _, fd := range proc.fds {
		fd.Close()
	}

	proc.SetState(SZOMB)

	return err
}

func (proc *Process) runEvaluator() error {
	// Receive peer uuid, pid, and program.
	peerUUID, err := proc.conn.ReceiveData()
	if err != nil {
		return err
	}
	var uid uuid.UUID
	uid.Set(peerUUID)
	fmt.Printf("Peer UUID %v\n", uid)

	gid, err := proc.conn.ReceiveUint16()
	if err != nil {
		return err
	}
	proc.pid.SetG(PartyID(gid))
	programName, err := proc.conn.ReceiveString()
	if err != nil {
		return err
	}
	prog, err := eef.NewProgram(programName)
	if err != nil {
		return err
	}
	err = proc.SetProgram(prog)
	if err != nil {
		return err
	}

	// Send our uuid and pid.
	err = proc.conn.SendData(proc.uuid[:])
	if err != nil {
		return err
	}
	err = proc.conn.SendUint16(int(proc.pid.E()))
	if err != nil {
		return err
	}
	err = proc.conn.Flush()
	if err != nil {
		return err
	}

	// if circ.NumParties() != 2 {
	// 	return fmt.Errorf("invalid circuit for 2-party MPC: %d parties",
	// 		circ.NumParties())
	// }

	// Run program.
	state := prog.Init
	sys := new(syscall)
	last := time.Now()

run:
	for {
		var ok bool
		var numInputs int
		var inputs []string

		if state.Circ != nil {
			numInputs = state.Circ.Inputs[1].Len()
		} else {
			// Dynamic MPCL has always full signature.
			numInputs = 3
		}

		// The first input is always the key share.
		inputs = append(inputs, fmt.Sprintf("0x%x", proc.key))
		if numInputs > 1 {
			inputs = append(inputs, fmt.Sprintf("%d", sys.arg0))
		}
		if numInputs > 2 {
			if len(sys.argBuf) == 0 {
				inputs = append(inputs, "0")
			} else {
				inputs = append(inputs, fmt.Sprintf("0x%x", sys.argBuf))
			}
		}

		var outputs circuit.IO
		var result []*big.Int
		var stats Stats

		if state.Circ != nil {
			// Pre-compiled circuit.
			proc.circuitStats(&stats, state.Circ)
			if proc.diagnostics() {
				state.Circ.PrintInputs(circuit.IDEvaluator, inputs)
			}

			input, err := state.Circ.Inputs[1].Parse(inputs)
			if err != nil {
				return err
			}
			result, err = circuit.Evaluator(proc.conn, proc.oti, state.Circ,
				input, proc.verbose())
			if err != nil {
				return err
			}
			outputs = state.Circ.Outputs

			if proc.diagnostics() {
				mpc.PrintResults(result, state.Circ.Outputs)
			}
		} else {
			// Streaming MPCL.
			sizes, err := circuit.InputSizes(inputs)
			if err != nil {
				return err
			}
			err = proc.conn.SendInputSizes(sizes)
			if err != nil {
				return err
			}
			err = proc.conn.Flush()
			if err != nil {
				return err
			}
			outputs, result, err = circuit.StreamEvaluator(proc.conn,
				proc.oti, inputs, proc.verbose())
			if err != nil {
				return err
			}
			if proc.diagnostics() {
				mpc.PrintResults(result, outputs)
			}
		}

		// Program fragment statistics.
		now := time.Now()
		stats.MPCD = now.Sub(last)
		last = now
		proc.ktraceStats(stats)

		// Decode syscall.
		err = decodeSysall(sys, mpc.Results(result, outputs))
		if err != nil {
			return err
		}
		proc.ktraceCall(sys)

		switch sys.call {
		case SysExit:
			proc.exitVal = sys.arg0
			break run

		case SysSpawn:
			sys.arg0 = 0
			sys.argBuf = nil
			sys.arg1 = 0

		case SysRead:
			sys.arg0 = 0
			sys.argBuf = nil

		case SysWrite:
			sys.arg0 = 0
			sys.argBuf = nil

		case SysWait:
			pid := PID(sys.arg0).E()
			child, ok := proc.kern.GetProcess(pid)
			if !ok {
				sys.arg0 = int32(-ECHILD)
			} else {
				child.WaitState(SZOMB)
				sys.arg0 = child.exitVal
				proc.kern.RemoveProcess(pid)
			}

		case SysYield:
			sys.arg0 = 0
			sys.argBuf = nil

		default:
			return fmt.Errorf("invalid syscall: %v", sys.call)
		}
		proc.ktraceRet(sys)

		proc.pc = sys.pc
		state, ok = proc.prog.ByPC[int(proc.pc)]
		if !ok {
			return fmt.Errorf("invalid PC: %v", proc.pc)
		}
	}
	return nil
}

func (proc *Process) runGarbler() error {
	if len(proc.prog.Filename) == 0 {
		return errors.New("no program")
	}

	// Run program.
	state := proc.prog.Init
	sys := new(syscall)
	inputSizes := make([][]int, 2)
	last := time.Now()

run:
	for {
		var ok bool
		var numInputs int
		var inputs []string

		if state.Circ != nil {
			numInputs = state.Circ.Inputs[0].Len()
		} else {
			// Dynamic MPCL has always full signature
			numInputs = 5
		}

		// The first input is always the key share.
		inputs = append(inputs, fmt.Sprintf("0x%x", proc.key))
		if numInputs > 1 {
			if len(proc.mem) == 0 {
				inputs = append(inputs, "0")
			} else {
				inputs = append(inputs, fmt.Sprintf("0x%x", proc.mem))
			}
		}
		if numInputs > 2 {
			inputs = append(inputs, fmt.Sprintf("%d", sys.arg0))
		}
		if numInputs > 3 {
			if len(sys.argBuf) == 0 {
				inputs = append(inputs, "0")
			} else {
				inputs = append(inputs, fmt.Sprintf("0x%x", sys.argBuf))
			}
		}
		if numInputs > 4 {
			inputs = append(inputs, fmt.Sprintf("%d", sys.arg1))
		}

		// Clear statistics so we get correct info for this code
		// fragment.
		proc.iostats = proc.iostats.Add(proc.conn.Stats)
		proc.conn.Stats.Clear()

		var outputs circuit.IO
		var result []*big.Int
		var stats Stats

		if state.Circ != nil {
			// Pre-compiled circuit.
			proc.circuitStats(&stats, state.Circ)
			if proc.diagnostics() {
				state.Circ.PrintInputs(circuit.IDGarbler, inputs)
			}

			input, err := state.Circ.Inputs[0].Parse(inputs)
			if err != nil {
				return err
			}
			result, err = circuit.Garbler(proc.conn, proc.oti, state.Circ,
				input, proc.verbose())
			if err != nil {
				return err
			}
			outputs = state.Circ.Outputs

			if proc.diagnostics() {
				mpc.PrintResults(result, state.Circ.Outputs)
			}
		} else {
			// Streaming MPCL.
			sizes, err := circuit.InputSizes(inputs)
			if err != nil {
				return err
			}
			inputSizes[0] = sizes

			sizes, err = proc.conn.ReceiveInputSizes()
			if err != nil {
				return err
			}
			inputSizes[1] = sizes

			outputs, result, err = compiler.New(proc.mpclcParams).Stream(
				proc.conn, proc.oti, state.Name, bytes.NewReader(state.DMPCL),
				inputs, inputSizes)
			if err != nil {
				return err
			}
			if proc.diagnostics() {
				mpc.PrintResults(result, outputs)
			}
		}

		// Program fragment statistics.
		now := time.Now()
		stats.MPCD = now.Sub(last)
		last = now
		proc.ktraceStats(stats)

		// Decode syscall.
		err := decodeSysall(sys, mpc.Results(result, outputs))
		if err != nil {
			return err
		}
		if len(sys.mem) > 0 {
			// Store memory only if returned.
			proc.mem = sys.mem
		}
		proc.ktraceCall(sys)

		switch sys.call {
		case SysExit:
			proc.exitVal = sys.arg0
			break run

		case SysSpawn:
			cmd := "bin/" + string(sys.argBuf[:sys.arg1])

			sys.argBuf = nil
			sys.arg1 = 0

			child, err := proc.kern.Spawn(cmd, proc.fds[0].Copy(),
				proc.fds[1].Copy(), proc.fds[2].Copy())
			if err != nil {
				sys.arg0 = int32(-ENOENT)
			} else {
				sys.arg0 = int32(child.pid)
				go child.Run()
			}

		case SysRead:
			fd, ok := proc.fds[sys.arg0]
			if !ok {
				sys.arg0 = int32(-EBADF)
			} else {
				sys.argBuf = make([]byte, int(sys.arg1))
				sys.arg0 = int32(fd.Read(sys.argBuf))
				sys.argBuf = sys.argBuf[:sys.arg0]
			}
			sys.arg1 = 0

		case SysWrite:
			fd, ok := proc.fds[sys.arg0]
			if !ok {
				sys.arg0 = int32(-EBADF)
			} else {
				sys.arg0 = int32(fd.Write(sys.argBuf[:sys.arg1]))
			}
			sys.argBuf = nil
			sys.arg1 = 0

		case SysWait:
			pid := PID(sys.arg0).E()
			child, ok := proc.kern.GetProcess(pid)
			if !ok {
				sys.arg0 = int32(-ECHILD)
			} else {
				child.WaitState(SZOMB)
				sys.arg0 = child.exitVal
				proc.kern.RemoveProcess(pid)
			}

		case SysYield:
			sys.arg0 = 0
			sys.argBuf = nil

		default:
			return fmt.Errorf("invalid syscall: %v", sys.call)
		}
		proc.ktraceRet(sys)

		proc.pc = sys.pc
		state, ok = proc.prog.ByPC[int(proc.pc)]
		if !ok {
			return fmt.Errorf("invalid PC: %v", proc.pc)
		}
	}

	return nil
}

func (proc *Process) circuitStats(stats *Stats, circ *circuit.Circuit) {
	stats.NumGates = uint64(circ.NumGates)
	stats.NumWires = uint64(circ.NumWires)
	stats.NumXOR = circ.Stats[circuit.XOR] + circ.Stats[circuit.XNOR]
	stats.NumNonXOR = circ.Stats[circuit.AND] + circ.Stats[circuit.OR] +
		circ.Stats[circuit.INV]
}

type syscall struct {
	mem    []byte
	pc     uint16
	call   Syscall
	arg0   int32
	argBuf []byte
	arg1   int32
}

func (sys *syscall) Print() {
	fmt.Printf("pc=%v, call=%v, arg0=%v, arg1=%v, arg2=%v\n",
		sys.pc, sys.call, sys.arg0, sys.argBuf, sys.arg1)
}

func decodeSysall(sys *syscall, values []interface{}) error {
	var ok bool

	// Memory.
	sys.mem, ok = values[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid memory: %T", values[0])
	}

	// PC.
	sys.pc, ok = values[1].(uint16)
	if !ok {
		return fmt.Errorf("invalid PC: %T", values[1])
	}

	// Syscall.
	call, ok := values[2].(uint8)
	if !ok {
		return fmt.Errorf("invalid syscall: %T", values[2])
	}
	sys.call = Syscall(call)

	// arg0.
	sys.arg0, ok = values[3].(int32)
	if !ok {
		return fmt.Errorf("invalid arg0: %T", values[3])
	}

	// argBuf.
	sys.argBuf, ok = values[4].([]byte)
	if !ok {
		return fmt.Errorf("invalid argBuf: %T", values[4])
	}

	// arg1.
	sys.arg1, ok = values[5].(int32)
	if !ok {
		return fmt.Errorf("invalid arg1: %T", values[5])
	}

	return nil
}

func (proc *Process) ktracePrefix() {
	if !proc.kern.Params.Trace {
		return
	}
	fmt.Printf("%7s %3d %-8s ", proc.pid, proc.pc, proc.prog.Name)
}

func (proc *Process) ktraceStats(stats Stats) {
	if !proc.kern.Params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("INFO %v", stats)
	fmt.Println()
}

func (proc *Process) ktraceCall(sys *syscall) {
	if !proc.kern.Params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("CALL %s", sys.call)
	switch sys.call {
	case SysExit, SysWait:
		fmt.Printf("(%d)", sys.arg0)

	case SysSpawn:
		fmt.Printf("(%s)", sys.argBuf[:sys.arg1])

	case SysRead:
		fmt.Printf("(%d, %d)", sys.arg0, sys.arg1)

	case SysWrite:
		fmt.Printf("(%d, %x, %d)", sys.arg0, sys.argBuf[:sys.arg1], sys.arg1)

	case SysYield:
		fmt.Printf("(%d)", sys.pc)
	}
	fmt.Println()
}

func (proc *Process) ktraceRet(sys *syscall) {
	if !proc.kern.Params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("RET  %s", sys.call)
	switch sys.call {
	case SysRead:
		fmt.Printf("% d, %x", sys.arg0, sys.argBuf)
	default:
		fmt.Printf(" %d", sys.arg0)
	}
	fmt.Println()
}
