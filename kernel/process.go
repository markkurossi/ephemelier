//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/markkurossi/ephemelier/eef"
	"github.com/markkurossi/mpc"
	"github.com/markkurossi/mpc/circuit"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

const (
	verboseMPC = false
)

var (
	oti = ot.NewCO()
)

// Process defines a kernel process.
type Process struct {
	kern *Kernel
	role Role
	conn *p2p.Conn
	prog *eef.Program
	key  []byte
	mem  []byte
	pc   uint16
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
			var inputs []string

			// The first input is always the key share.
			inputs = append(inputs, fmt.Sprintf("0x%x", proc.key))
			if state.Name != "Init" {
				inputs = append(inputs, fmt.Sprintf("%d", sys.arg0))
				if len(sys.argBuf) == 0 {
					inputs = append(inputs, "0")
				} else {
					inputs = append(inputs, fmt.Sprintf("0x%x", sys.argBuf))
				}
			}

			if verboseMPC {
				state.Circ.PrintInputs(circuit.IDEvaluator, inputs)
			}

			input, err := state.Circ.Inputs[1].Parse(inputs)
			if err != nil {
				return err
			}
			result, err := circuit.Evaluator(proc.conn, oti, state.Circ,
				input, verboseMPC)
			if err != nil {
				return err
			}
			if verboseMPC {
				mpc.PrintResults(result, state.Circ.Outputs)
			}

			// Decode syscall.
			err = decodeSysall(sys, mpc.Results(result, state.Circ.Outputs))
			if err != nil {
				return err
			}
			if false {
				sys.Print()
			}
			strace(proc.pc, sys)

			switch sys.call {
			case SysExit:
				break run

			case SysWrite:
				sys.arg0 = 0
				sys.argBuf = nil
			}

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
	if len(proc.prog.Name) == 0 {
		return errors.New("no program")
	}
	err := proc.conn.SendString(proc.prog.Name)
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
run:
	for {
		var ok bool
		var inputs []string

		// The first input is always the key share.
		inputs = append(inputs, fmt.Sprintf("0x%x", proc.key))
		if state.Name != "Init" {
			inputs = append(inputs, fmt.Sprintf("0x%x", proc.mem))
			inputs = append(inputs, fmt.Sprintf("%d", sys.arg0))
			if len(sys.argBuf) == 0 {
				inputs = append(inputs, "0")
			} else {
				inputs = append(inputs, fmt.Sprintf("0x%x", sys.argBuf))
			}
			inputs = append(inputs, fmt.Sprintf("%d", sys.arg1))
		}

		if verboseMPC {
			state.Circ.PrintInputs(circuit.IDGarbler, inputs)
		}

		input, err := state.Circ.Inputs[0].Parse(inputs)
		if err != nil {
			return err
		}
		result, err := circuit.Garbler(proc.conn, oti, state.Circ, input,
			verboseMPC)
		if err != nil {
			return err
		}
		if verboseMPC {
			mpc.PrintResults(result, state.Circ.Outputs)
		}

		// Decode syscall.
		err = decodeSysall(sys, mpc.Results(result, state.Circ.Outputs))
		if err != nil {
			return err
		}
		if len(sys.mem) > 0 {
			// Store memory only if returned.
			proc.mem = sys.mem
		}
		if false {
			sys.Print()
		}
		strace(proc.pc, sys)

		proc.pc = sys.pc

		switch sys.call {
		case SysExit:
			break run

		case SysWrite:
			n, err := os.Stdout.Write(sys.argBuf[:sys.arg1])
			if err != nil {
				sys.arg0 = -22
			} else {
				sys.arg0 = int32(n)
			}
			sys.argBuf = nil
			sys.arg1 = 0
		}

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

func strace(pc uint16, sys *syscall) {
	fmt.Printf("%04x: %s", pc, sys.call)
	switch sys.call {
	case SysExit:
		fmt.Printf("(%d)", sys.arg0)

	case SysWrite:
		fmt.Printf("(%d, %x, %d)", sys.arg0, sys.argBuf[:sys.arg1], sys.arg1)
	}
	fmt.Println()

}
