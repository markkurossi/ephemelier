//
// Copyright (c) 2025-2026 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/markkurossi/ephemelier/eef"
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
	args        []string
	pid         PID
	cwd         string
	root        string
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
	rusage      RUsage
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

// RUsage provides process resource usage information.
type RUsage struct {
	Utime      time.Duration
	Stime      time.Duration
	CompTime   time.Duration
	StreamTime time.Duration
	GarbleTime time.Duration
	NumGates   uint64
	NumWires   uint64
	NumXOR     uint64
	NumNonXOR  uint64
}

// Add adds the argument RUsage data to this RUsage instance.
func (rusage *RUsage) Add(o RUsage) {
	rusage.Utime += o.Utime
	rusage.Stime += o.Stime
	rusage.CompTime += o.CompTime
	rusage.StreamTime += o.StreamTime
	rusage.GarbleTime += o.GarbleTime
	rusage.NumGates += o.NumGates
	rusage.NumWires += o.NumWires
	rusage.NumXOR += o.NumXOR
	rusage.NumNonXOR += o.NumNonXOR
}

func (rusage RUsage) String() string {
	return fmt.Sprintf("g=%v xor=%v nxor=%v utime=%v",
		rusage.NumGates, rusage.NumXOR, rusage.NumNonXOR, rusage.Utime)
}

func (proc *Process) diagnostics() bool {
	return proc.kern.params.Diagnostics
}

func (proc *Process) verbose() bool {
	return proc.kern.params.Verbose
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
	proc.prog = prog

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

// AllocFD allocates a file descriptor for the FD implementation.
func (proc *Process) AllocFD(fd *FD) int32 {
	proc.m.Lock()
	defer proc.m.Unlock()

	var ret int32
	for ret = 0; ; ret++ {
		_, ok := proc.fds[ret]
		if !ok {
			proc.fds[ret] = fd
			return ret
		}
	}
}

// SetFD sets the FD implementation for the file descriptor.
func (proc *Process) SetFD(fd int32, impl *FD) error {
	proc.m.Lock()
	defer proc.m.Unlock()

	_, ok := proc.fds[fd]
	if ok {
		return fmt.Errorf("fd %v already set", fd)
	}
	proc.fds[fd] = impl

	return nil
}

// FreeFD frees the file descriptor.
func (proc *Process) FreeFD(fd int32) {
	proc.m.Lock()
	defer proc.m.Unlock()

	delete(proc.fds, fd)
}

// Run runs the process.
func (proc *Process) Run() (err error) {
	defer proc.conn.Close()

	proc.SetState(SRUN)

	switch proc.role {
	case RoleGarbler:
		err = proc.runGarbler()
	case RoleEvaluator:
		err = proc.runEvaluator()
	}
	if err != nil {
		proc.ktracePrefix()
		fmt.Printf("process error: %v\n", err)
	}
	// Close all FDs.
	for _, fd := range proc.fds {
		fd.Close()
	}
	// XXX Close process port. If parent queried port, FD's refcount
	// is 2 and it was not closed above.

	proc.SetState(SZOMB)

	return err
}

func (proc *Process) runEvaluator() error {
	// Receive peer pid and program.
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

	// Send our pid.
	err = proc.conn.SendUint16(int(proc.pid.E()))
	if err != nil {
		return err
	}
	err = proc.conn.Flush()
	if err != nil {
		return err
	}

	// Run program.
	state := prog.Init
	sys := new(syscall)
	last := time.Now()

	// Init gets pid in arg0.
	sys.arg0 = int32(proc.pid)

run:
	for {
		var numInputs int
		var input *big.Int

		inputs := make([]interface{}, 3)

		if state.Circ != nil {
			numInputs = state.Circ.Inputs[1].Len()
		} else {
			// Dynamic MPCL has always full signature.
			numInputs = 3
		}

		// The first input is always sys.arg0
		inputs[0] = sys.arg0

		// Key share.
		if numInputs > 1 {
			inputs[1] = proc.key
		}

		// Argument buffer.
		if numInputs > 2 {
			inputs[2] = sys.argBuf
		}

		var outputs circuit.IO
		var result []*big.Int

		now := time.Now()
		proc.rusage.Stime += now.Sub(last)
		last = now

		var rusage RUsage
		var err error

		if state.Circ != nil {
			// Pre-compiled circuit.
			proc.circuitStats(&rusage, state.Circ)
			input, err = state.Circ.Inputs[1].Set(input, inputs[:numInputs])
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
				mpc.PrintResults(result, state.Circ.Outputs, 0)
			}
		} else {
			// Streaming MPCL.
			sizes, err := circuit.Sizes(inputs[:numInputs])
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
				proc.oti, nil, inputs, proc.verbose())
			if err != nil {
				return err
			}
			if proc.diagnostics() {
				mpc.PrintResults(result, outputs, 0)
			}
		}

		// Program fragment statistics.
		now = time.Now()
		rusage.Utime += now.Sub(last)
		last = now
		proc.ktraceStats(rusage)
		proc.rusage.Add(rusage)

		// Decode syscall.
		err = proc.decodeSyscall(sys, mpc.Results(result, outputs))
		if err != nil {
			return err
		}
		proc.ktraceCall(sys)

		switch sys.call {
		case SysExit:
			proc.exitVal = sys.arg0
			break run

		case SysSpawn, SysDial, SysListen:
			// XXX SysDial should sync FD with garbler
			sys.SetArg0(0)

		case SysOpen:
			fd := NewDevNullFD()

			// Get FD from garbler.
			gfd, err := proc.recvFD()
			if err == nil {
				sys.SetArg0(int32(gfd))
				err = proc.SetFD(sys.arg0, fd)
			}
			if err != nil {
				fd.Close()
				sys.SetArg0(mapError(err))
			}

		case SysAccept:
			fd := NewSocketFD(NewConnDevNull())

			// Get FD from garbler.
			gfd, err := proc.conn.ReceiveUint32()
			if err == nil {
				sys.SetArg0(int32(gfd))
				err = proc.SetFD(sys.arg0, fd)
			}
			if err != nil {
				fd.Close()
				sys.SetArg0(mapError(err))
			}

		case SysChroot:
			sys.SetArg0(0)

		case SysOpenkey:
			name, err := sys.argString()
			if err != nil || len(name) == 0 {
				sys.SetArg0(int32(-EINVAL))
				return nil
			}
			fd, err := proc.openKey(name)
			if err != nil {
				sys.SetArg0(mapError(err))
				proc.conn.ReceiveUint32()
				return nil
			}

			// Get FD from garbler.
			gfd, err := proc.conn.ReceiveUint32()
			if err == nil {
				sys.SetArg0(int32(gfd))
				err = proc.SetFD(sys.arg0, fd)
			}
			if err != nil {
				fd.Close()
				sys.SetArg0(mapError(err))
			}

		case SysGetport:
			if sys.arg0 <= 0 {
				sys.SetArg0(int32(-EINVAL))
				break
			}

			pid := PID(sys.arg0)
			epid := pid.E()
			port, err := proc.kern.GetProcessPort(epid)
			if err != nil {
				sys.SetArg0(int32(-EINVAL))
				break
			}

			var fd *FD
			if pid == proc.pid {
				fd = port.NewServerFD()
			} else {
				fd = port.NewClientFD()
			}

			// Get FD from garbler.
			gfd, err := proc.conn.ReceiveUint32()
			if err == nil {
				sys.SetArg0(int32(gfd))
				err = proc.SetFD(sys.arg0, fd)
			}
			if err != nil {
				fd.Close()
				sys.SetArg0(int32(-EFAULT))
			}

		default:
			err = proc.syscall(sys)
			if err != nil {
				return err
			}
		}
		proc.ktraceRet(sys)

		state, err = proc.setPC(sys)
		if err != nil {
			return err
		}
	}

	proc.ktraceExit()

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

	// Init gets pid in arg0.
	sys.arg0 = int32(proc.pid)

	// Program arguments.
	// XXX format arguments to sys.argBuf.
	sys.arg1 = int32(len(proc.args))

run:
	for {
		var numInputs int
		var input *big.Int

		inputs := make([]interface{}, 5)

		if state.Circ != nil {
			numInputs = state.Circ.Inputs[0].Len()
		} else {
			// Dynamic MPCL has always full signature
			numInputs = 5
		}

		// The first input is always sys.arg0.
		inputs[0] = sys.arg0

		// Key share.
		if numInputs > 1 {
			inputs[1] = proc.key
		}

		// Program memory.
		if numInputs > 2 {
			inputs[2] = proc.mem
		}

		// Argument buffer.
		if numInputs > 3 {
			inputs[3] = sys.argBuf
		}

		// Optional sys.arg1.
		if numInputs > 4 {
			inputs[4] = sys.arg1
		}

		// Clear statistics so we get correct info for this code
		// fragment.
		proc.iostats = proc.iostats.Add(proc.conn.Stats)
		proc.conn.Stats.Clear()

		var outputs circuit.IO
		var result []*big.Int

		now := time.Now()
		proc.rusage.Stime += now.Sub(last)
		last = now

		var rusage RUsage
		var err error

		if state.Circ != nil {
			// Pre-compiled circuit.
			proc.circuitStats(&rusage, state.Circ)
			input, err = state.Circ.Inputs[0].Set(input, inputs[:numInputs])
			if err != nil {
				return err
			}
			start := time.Now()
			result, err = circuit.Garbler(proc.kern.params.MPCConfig,
				proc.conn, proc.oti, state.Circ, input, proc.verbose())
			if err != nil {
				return err
			}
			outputs = state.Circ.Outputs
			rusage.GarbleTime = time.Since(start)

			if proc.diagnostics() {
				mpc.PrintResults(result, state.Circ.Outputs, 0)
			}
		} else {
			// Streaming MPCL.
			sizes, err := circuit.Sizes(inputs[:numInputs])
			if err != nil {
				return err
			}
			inputSizes[0] = sizes

			sizes, err = proc.conn.ReceiveInputSizes()
			if err != nil {
				return err
			}
			inputSizes[1] = sizes

			start := time.Now()
			cc := compiler.New(proc.mpclcParams)
			prog, _, err := cc.CompileSSA(state.Name,
				bytes.NewReader(state.DMPCL), inputSizes)
			if err != nil {
				return err
			}
			rusage.CompTime = time.Since(start)

			input, err = prog.Inputs[0].Set(input, inputs[:numInputs])
			if err != nil {
				return err
			}

			timing := circuit.NewTiming()
			outputs, result, err = prog.Stream(proc.conn, proc.oti,
				proc.mpclcParams, input, timing)
			if err != nil {
				return err
			}
			if proc.diagnostics() {
				mpc.PrintResults(result, outputs, 0)
			}

			tStream := timing.Get("Stream")
			tGarble := tStream.Get("Garble")
			if tStream != nil && tGarble != nil {
				rusage.GarbleTime = tGarble.Duration()
				rusage.StreamTime = tStream.Duration() - rusage.GarbleTime
			}

			cstats := prog.Stats()
			rusage.NumGates = cstats.Count()
			rusage.NumXOR = cstats.NumXOR()
			rusage.NumNonXOR = cstats.NumNonXOR()
		}

		// Program fragment statistics.
		now = time.Now()
		rusage.Utime += now.Sub(last)
		last = now
		proc.ktraceStats(rusage)
		proc.rusage.Add(rusage)

		// Decode syscall.
		err = proc.decodeSyscall(sys, mpc.Results(result, outputs))
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
			command, err := sys.argString()
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}
			args := strings.Split(command, "\n")
			if len(args) == 0 {
				sys.SetArg0(int32(-EINVAL))
				break
			}
			cmd := "bin/" + args[0]
			args = args[1:]

			sys.argBuf = nil
			sys.arg1 = 0

			child, err := proc.kern.Spawn(cmd, args, proc.fds[0].Copy(),
				proc.fds[1].Copy(), proc.fds[2].Copy())
			if err != nil {
				sys.arg0 = int32(-ENOENT)
				break
			}
			sys.arg0 = int32(child.pid)
			go child.Run()

		case SysDial:
			addrData, err := sys.argData()
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}
			network, address, errno := ParseNetAddress(addrData)
			if errno != 0 {
				sys.SetArg0(-int32(errno))
				break
			}
			conn, err := net.Dial(network, address)
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}
			fd := NewSocketFD(conn)
			sys.SetArg0(proc.AllocFD(fd))
			// XXX sync fd with evaluator

		case SysListen:
			addrData, err := sys.argData()
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}
			network, address, errno := ParseNetAddress(addrData)
			if errno != 0 {
				sys.SetArg0(-int32(errno))
				break
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}
			fd := NewListenerFD(listener)
			sys.SetArg0(proc.AllocFD(fd))

		case SysOpen:
			path, err := sys.argString()
			if err != nil || len(path) == 0 {
				sys.SetArg0(int32(-EINVAL))
				proc.sendFD(int(-EINVAL))
				break
			}
			path = proc.MakePath(path)

			info, err := os.Stat(path)
			if err != nil {
				sys.SetArg0(mapError(err))
				proc.sendFD(int(sys.arg0))
				break
			}

			file, err := os.Open(path)
			if err != nil {
				sys.SetArg0(mapError(err))
				proc.sendFD(int(sys.arg0))
				break
			}
			fd := NewFileFD(file)
			sys.SetArg0(proc.AllocFD(fd))

			sys.argBuf = MakeFileInfo(info)

			// Sync FD with evaluator.
			err = proc.sendFD(int(sys.arg0))
			if err != nil {
				fd.Close()
				proc.FreeFD(sys.arg0)
				sys.SetArg0(mapError(err))
			}

		case SysAccept:
			fd, ok := proc.fds[sys.arg0]
			if !ok {
				sys.SetArg0(int32(-EBADF))
				break
			}
			listenerfd, ok := fd.Impl.(*FDListener)
			if !ok {
				sys.SetArg0(int32(-ENOTSOCK))
				break
			}
			conn, err := listenerfd.listener.Accept()
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}

			cfd := NewSocketFD(conn)
			sys.SetArg0(proc.AllocFD(cfd))

			// Sync FD with evaluator.
			err = proc.conn.SendUint32(int(sys.arg0))
			if err == nil {
				err = proc.conn.Flush()
			}
			if err != nil {
				cfd.Close()
				proc.FreeFD(sys.arg0)
				sys.SetArg0(mapError(err))
			}

		case SysChroot:
			path, err := sys.argString()
			if err != nil || len(path) == 0 {
				sys.SetArg0(int32(-EINVAL))
				break
			}
			err = proc.Chroot(path)
			if err != nil {
				sys.SetArg0(mapError(err))
				break
			}
			sys.SetArg0(0)

		case SysOpenkey:
			name, err := sys.argString()
			if err != nil || len(name) == 0 {
				sys.SetArg0(int32(-EINVAL))
				proc.sendFD(int(-EINVAL))
				return nil
			}
			fd, err := proc.openKey(name)
			if err != nil {
				sys.SetArg0(mapError(err))
				proc.sendFD(int(sys.arg0))
				return nil
			}
			sys.SetArg0(proc.AllocFD(fd))

			// Sync FD with evaluator.
			err = proc.conn.SendUint32(int(sys.arg0))
			if err == nil {
				err = proc.conn.Flush()
			}
			if err != nil {
				fd.Close()
				proc.FreeFD(sys.arg0)
				sys.SetArg0(mapError(err))
			}

		case SysGetport:
			if sys.arg0 <= 0 {
				sys.SetArg0(int32(-EINVAL))
				break
			}

			pid := PID(sys.arg0)
			gpid := pid.G()
			port, err := proc.kern.GetProcessPort(gpid)
			if err != nil {
				sys.SetArg0(int32(-EINVAL))
				break
			}
			var fd *FD
			if pid == proc.pid {
				fd = port.NewServerFD()
			} else {
				fd = port.NewClientFD()
			}
			sys.SetArg0(proc.AllocFD(fd))

			// Sync FD with evaluator.
			err = proc.conn.SendUint32(int(sys.arg0))
			if err == nil {
				err = proc.conn.Flush()
			}
			if err != nil {
				fd.Close()
				proc.FreeFD(sys.arg0)
				sys.SetArg0(int32(-EFAULT))
			}

		default:
			err = proc.syscall(sys)
			if err != nil {
				return err
			}
		}
		proc.ktraceRet(sys)

		state, err = proc.setPC(sys)
		if err != nil {
			return err
		}
	}

	proc.ktraceExit()

	return nil
}

func (proc *Process) syscall(sys *syscall) error {
	switch sys.call {
	case SysRead:
		fd, ok := proc.fds[sys.arg0]
		if !ok {
			sys.SetArg0(int32(-EBADF))
			return nil
		}
		sys.argBuf = make([]byte, int(sys.arg1))
		sys.arg0 = int32(fd.Read(sys.argBuf))
		if sys.arg0 > 0 {
			sys.argBuf = sys.argBuf[:sys.arg0]
		} else {
			sys.argBuf = nil
		}
		sys.arg1 = 0

	case SysWrite:
		fd, ok := proc.fds[sys.arg0]
		if !ok {
			sys.SetArg0(int32(-EBADF))
			return nil
		}
		data, err := sys.argData()
		if err != nil {
			sys.SetArg0(mapError(err))
			return nil
		}
		sys.SetArg0(int32(fd.Write(data)))

	case SysClose:
		fd, ok := proc.fds[sys.arg0]
		if !ok {
			sys.SetArg0(int32(-EBADF))
			return nil
		}
		sys.SetArg0(int32(fd.Close()))
		proc.FreeFD(sys.arg0)

	case SysWait:
		var pid PartyID
		if proc.role == RoleGarbler {
			pid = PID(sys.arg0).G()
		} else {
			pid = PID(sys.arg0).E()
		}
		child, ok := proc.kern.GetProcess(pid)
		if !ok {
			sys.SetArg0(int32(-ECHILD))
			return nil
		}
		child.WaitState(SZOMB)
		sys.SetArg0(child.exitVal)
		proc.kern.RemoveProcess(pid)

	case SysTlsserver:
		proc.tlsServer(sys)

	case SysTlshs:
		proc.tlsHandshake(sys)

	case SysTlsstatus:
		proc.tlsStatus(sys)

	case SysGetrandom:
		buf := make([]byte, sys.arg0)
		n, err := rand.Read(buf)
		if err != nil {
			sys.SetArg0(int32(-EFAULT))
			return nil
		}
		sys.arg0 = int32(n)
		sys.argBuf = buf
		sys.arg1 = 0

	case SysContinue:
		// Clear values.
		sys.SetArg0(0)

	case SysYield:
		// The decodeSyscall has preserved the old values.

	case SysNext:
		// Use the new values provided for the syscall.

	case SysGetpid:
		sys.SetArg0(int32(proc.pid))

	case SysSendfd:
		fd, ok := proc.fds[sys.arg0]
		if !ok {
			sys.SetArg0(int32(-EBADF))
			return nil
		}
		portfd, ok := fd.Impl.(*FDPort)
		if !ok {
			sys.SetArg0(int32(-EINVAL))
			return nil
		}
		sendfd, ok := proc.fds[sys.arg1]
		if !ok {
			sys.SetArg0(int32(-EINVAL))
			return nil
		}
		proc.FreeFD(sys.arg1)
		sys.SetArg0(int32(portfd.SendFD(sendfd)))

	case SysRecvfd:
		fd, ok := proc.fds[sys.arg0]
		if !ok {
			sys.arg0 = int32(-EBADF)
			return nil
		}
		portfd, ok := fd.Impl.(*FDPort)
		if !ok {
			sys.SetArg0(int32(-EINVAL))
			return nil
		}
		recvfd, errno := portfd.RecvFD()
		if errno != 0 {
			sys.SetArg0(int32(errno))
			return nil
		}

		var err error

		if proc.role == RoleGarbler {
			sys.SetArg0(proc.AllocFD(recvfd))

			// Sync FD with evaluator.
			err = proc.conn.SendUint32(int(sys.arg0))
			if err == nil {
				err = proc.conn.Flush()
			}
			if err != nil {
				proc.FreeFD(sys.arg0)
			}
		} else {
			// Get FD from garbler.
			var gfd int
			gfd, err = proc.conn.ReceiveUint32()
			if err == nil {
				sys.SetArg0(int32(gfd))
				err = proc.SetFD(sys.arg0, recvfd)
			}
		}
		if err != nil {
			recvfd.Close()
			sys.SetArg0(int32(-EFAULT))
		}

	case SysCreatemsg:
		sys.argBuf = nil
		sys.arg1 = 0

		fd, ok := proc.fds[sys.arg0]
		if !ok {
			sys.SetArg0(int32(-EBADF))
			return nil
		}
		portfd, ok := fd.Impl.(*FDPort)
		if !ok {
			sys.SetArg0(int32(-EBADF))
			return nil
		}
		sys.argBuf = portfd.CreateMsg()
		sys.arg0 = int32(len(sys.argBuf))

	default:
		return fmt.Errorf("invalid syscall: %v", sys.call)
	}

	return nil
}

func (proc *Process) sendFD(fd int) error {
	err := proc.conn.SendUint32(fd)
	if err != nil {
		return err
	}
	return proc.conn.Flush()
}

func (proc *Process) recvFD() (int, error) {
	fd, err := proc.conn.ReceiveUint32()
	if err != nil {
		return int(-EINVAL), err
	}
	if int32(fd) < 0 {
		return int(-EINVAL), Errno(-int32(fd))
	}
	return int(fd), nil
}

func (proc *Process) setPC(sys *syscall) (*eef.Circuit, error) {
	state, ok := proc.prog.ByPC[int(sys.pc)]
	if !ok {
		return nil, fmt.Errorf("%s (%s): program state %v not found",
			proc.prog.Name, proc.pid, proc.prog.StateName(int(sys.pc)))
	}
	proc.pc = sys.pc

	return state, nil
}

func (proc *Process) circuitStats(rusage *RUsage, circ *circuit.Circuit) {
	rusage.NumGates = uint64(circ.NumGates)
	rusage.NumWires = uint64(circ.NumWires)
	rusage.NumXOR = circ.Stats.NumXOR()
	rusage.NumNonXOR = circ.Stats.NumNonXOR()
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

func (sys *syscall) argString() (string, error) {
	if sys.arg1 < 0 || int(sys.arg1) > len(sys.argBuf) {
		return "", EINVAL
	}
	return string(sys.argBuf[:sys.arg1]), nil
}

func (sys *syscall) argData() ([]byte, error) {
	if sys.arg1 < 0 || int(sys.arg1) > len(sys.argBuf) {
		return nil, EINVAL
	}
	return sys.argBuf[:sys.arg1], nil
}

func (sys *syscall) SetArg0(arg0 int32) {
	sys.arg0 = arg0
	sys.argBuf = nil
	sys.arg1 = 0
}

func (proc *Process) decodeSyscall(sys *syscall, values []interface{}) error {
	var ok bool

	if len(values) < 4 {
		return fmt.Errorf("too few return values, got %v, expected 4",
			len(values))
	}

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
	if sys.call == SysYield {
		// Yield with preserved values. We are done.
		proc.debugSyscall(values)
		return nil
	}

	// arg0.
	arg0, ok := values[3].(int32)
	if !ok {
		return fmt.Errorf("invalid arg0: %T", values[3])
	}
	sys.arg0 = arg0

	// argBuf.
	if len(values) > 4 {
		sys.argBuf, ok = values[4].([]byte)
		if !ok {
			return fmt.Errorf("invalid argBuf: %T", values[4])
		}
	} else {
		sys.argBuf = nil
	}

	// arg1.
	if len(values) > 5 {
		sys.arg1, ok = values[5].(int32)
		if !ok {
			return fmt.Errorf("invalid arg1: %T", values[5])
		}
	} else {
		sys.arg1 = 0
	}

	proc.debugSyscall(values)

	return nil
}

func (proc *Process) debugSyscall(values []interface{}) {
	if !proc.kern.params.Trace {
		return
	}
	// Print any additional debug values.
	for i := 6; i < len(values); i++ {
		proc.ktracePrefix()
		switch v := values[i].(type) {
		case []byte:
			fmt.Printf("DBG  %x", v)
		default:
			fmt.Printf("DBG  %v", v)
		}
		fmt.Println()
	}
}

func (proc *Process) debugf(format string, a ...interface{}) {
	if !proc.kern.params.Diagnostics {
		return
	}
	fmt.Printf("%s: ", proc.prog.Name)
	fmt.Printf(format, a...)
}
