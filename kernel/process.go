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
	"io"
	"log"
	"math/big"

	"github.com/markkurossi/ephemelier/eef"
	"github.com/markkurossi/mpc"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/compiler"
	"github.com/markkurossi/mpc/compiler/utils"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var (
	oti = ot.NewCO()
)

// Process defines a kernel process.
type Process struct {
	kern        *Kernel
	role        Role
	pid         int32
	conn        *p2p.Conn
	iostats     p2p.IOStats
	prog        *eef.Program
	mpclcParams *utils.Params
	key         []byte
	mem         []byte
	pc          uint16
	fds         map[int32]*FD
}

func (proc *Process) diagnostics() bool {
	return proc.kern.Params.Diagnostics
}

func (proc *Process) verbose() bool {
	return proc.kern.Params.Verbose
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

	return err
}

func (proc *Process) runEvaluator() error {
	for {
		// Receive program.
		programName, err := proc.conn.ReceiveString()
		if err != nil {
			if err == io.EOF {
				return nil
			}
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
		// if circ.NumParties() != 2 {
		// 	return fmt.Errorf("invalid circuit for 2-party MPC: %d parties",
		// 		circ.NumParties())
		// }

		// Run program.
		state := prog.Init
		sys := new(syscall)

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

			if state.Circ != nil {
				// Pre-compiled circuit.
				if proc.diagnostics() {
					state.Circ.PrintInputs(circuit.IDEvaluator, inputs)
				}

				input, err := state.Circ.Inputs[1].Parse(inputs)
				if err != nil {
					return err
				}
				result, err = circuit.Evaluator(proc.conn, oti, state.Circ,
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
				outputs, result, err = circuit.StreamEvaluator(proc.conn, oti,
					inputs, proc.verbose())
				if err != nil {
					return err
				}
				if proc.diagnostics() {
					mpc.PrintResults(result, outputs)
				}
			}

			// Decode syscall.
			err = decodeSysall(sys, mpc.Results(result, outputs))
			if err != nil {
				return err
			}
			proc.ktraceCall(sys)

			switch sys.call {
			case SysExit:
				break run

			case SysRead:
				sys.arg0 = 0
				sys.argBuf = nil

			case SysWrite:
				sys.arg0 = 0
				sys.argBuf = nil

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
	}
}

func (proc *Process) runGarbler() error {
	// Send program name
	if len(proc.prog.Filename) == 0 {
		return errors.New("no program")
	}
	err := proc.conn.SendString(proc.prog.Filename)
	if err != nil {
		return err
	}
	err = proc.conn.Flush()
	if err != nil {
		return err
	}

	// Run program.
	state := proc.prog.Init
	sys := new(syscall)
	inputSizes := make([][]int, 2)
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

		if state.Circ != nil {
			// Pre-compiled circuit.
			if proc.diagnostics() {
				state.Circ.PrintInputs(circuit.IDGarbler, inputs)
			}

			input, err := state.Circ.Inputs[0].Parse(inputs)
			if err != nil {
				return err
			}
			result, err = circuit.Garbler(proc.conn, oti, state.Circ, input,
				proc.verbose())
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
				proc.conn, oti, state.Name, bytes.NewReader(state.DMPCL),
				inputs, inputSizes)
			if err != nil {
				return err
			}
			if proc.diagnostics() {
				mpc.PrintResults(result, outputs)
			}
		}

		// Decode syscall.
		err = decodeSysall(sys, mpc.Results(result, outputs))
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
			break run

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
	fmt.Printf("%3d %4d %-8s ", proc.pid, proc.pc, proc.prog.Name)
}

func (proc *Process) ktraceCall(sys *syscall) {
	if !proc.kern.Params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("CALL %s", sys.call)
	switch sys.call {
	case SysExit:
		fmt.Printf("(%d)", sys.arg0)

	case SysRead:
		fmt.Printf("(%d, %d)", sys.arg0, sys.arg1)

	case SysWrite:
		fmt.Printf("(%d, %x, %d)", sys.arg0, sys.argBuf[:sys.arg1], sys.arg1)
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
