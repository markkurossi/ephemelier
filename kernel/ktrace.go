//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

func (proc *Process) ktracePrefix() {
	if !proc.kern.params.Trace {
		return
	}
	fmt.Printf("%7s %3d %-8s ", proc.pid, proc.pc, proc.prog.Name)
}

func (proc *Process) ktraceStats(rusage RUsage) {
	if !proc.kern.params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("INFO %v", rusage)
	fmt.Println()
}

func (proc *Process) ktraceHex(data []byte) {
	if !proc.kern.params.TraceHex {
		return
	}
	dump := hex.Dump(data)
	lines := strings.Split(dump, "\n")

	var separator = "    -------------------------------------------------------------------------"
	fmt.Println()
	fmt.Println(separator)

	for idx, line := range lines {
		var n string
		for i := 1; i < len(line); i++ {
			if line[i] == '0' && i+1 < len(line) && line[i+1] != ' ' {
				n = n + " "
			} else {
				n += line[i:]
				break
			}
		}
		if idx+1 < len(lines) || len(n) > 0 {
			fmt.Println(n)
		}
	}
	fmt.Print(separator)
}

func (proc *Process) ktraceCall(sys *syscall) {
	if !proc.kern.params.Trace {
		return
	}
	const dataLimit = 16

	proc.ktracePrefix()
	fmt.Printf("CALL %s", sys.call)
	switch sys.call {
	case SysExit, SysClose, SysWait, SysCreatemsg, SysAccept,
		SysTlsstatus, SysRecvfd:
		fmt.Printf("(%d)", sys.arg0)

	case SysSpawn, SysDial, SysListen:
		fmt.Printf("(%q)", string(sys.argBuf[:sys.arg1]))

	case SysRead, SysTlsserver, SysTlsclient, SysSendfd:
		fmt.Printf("(%d, %d)", sys.arg0, sys.arg1)

	case SysTlskex:
		ht := tls.HandshakeType(sys.arg1)
		fmt.Printf("(%d, ", sys.arg0)
		if len(sys.argBuf) <= dataLimit {
			fmt.Printf("%x, %s)", sys.argBuf, ht)
		} else {
			fmt.Printf("%x..., %d)", sys.argBuf[:dataLimit], ht)
			proc.ktraceHex(sys.argBuf)
		}

	case SysWrite:
		fmt.Printf("(%d, ", sys.arg0)
		if sys.arg1 <= dataLimit {
			fmt.Printf("%x, %d)", sys.argBuf[:sys.arg1], sys.arg1)
		} else {
			fmt.Printf("%x..., %d)", sys.argBuf[:dataLimit], sys.arg1)
			proc.ktraceHex(sys.argBuf)
		}

	case SysContinue, SysYield:
		fmt.Printf("(%d)", sys.pc)

	case SysNext:
		fmt.Printf("(%d, %d, ", sys.pc, sys.arg0)
		if len(sys.argBuf) <= dataLimit {
			fmt.Printf("%x, %v)", sys.argBuf, sys.arg1)
		} else {
			fmt.Printf("%x..., %d)", sys.argBuf[:dataLimit], sys.arg1)
			proc.ktraceHex(sys.argBuf)
		}

	case SysGetport:
		if sys.arg1 > 0 {
			fmt.Printf("(%s)", sys.argBuf[:sys.arg0])
		} else {
			fmt.Printf("(%s)", PID(sys.arg0))
		}
	}
	fmt.Println()
}

func (proc *Process) ktraceRet(sys *syscall) {
	if !proc.kern.params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("RET  %s ", sys.call)
	if sys.arg0 < 0 {
		fmt.Printf("%d %s", sys.arg0, Errno(-sys.arg0))
	} else {
		switch sys.call {
		case SysSpawn:
			fmt.Printf("%s", PID(sys.arg0))

		case SysRead, SysCreatemsg, SysTlsserver:
			fmt.Printf("%d", sys.arg0)
			if len(sys.argBuf) > 0 {
				proc.ktraceHex(sys.argBuf)
			} else {
				fmt.Printf(", nil")
			}

		case SysTlskex:
			fmt.Printf("%d %s", sys.arg0, tls.HandshakeType(sys.arg0))
			if len(sys.argBuf) > 0 {
				fmt.Printf(", %d bytes", len(sys.argBuf))
				proc.ktraceHex(sys.argBuf)
			} else {
				fmt.Printf(", nil")
			}

		default:
			fmt.Printf("%d", sys.arg0)
		}
	}
	fmt.Println()
}

func (proc *Process) ktraceExit() {
	if !proc.kern.params.Trace {
		return
	}
	proc.ktracePrefix()
	fmt.Printf("EXIT %v\n", proc.exitVal)

	proc.ktracePrefix()
	fmt.Printf("RUSG utime=%v, stime=%v\n", proc.rusage.Utime,
		proc.rusage.Stime)

	proc.ktracePrefix()
	fmt.Printf("RUSG c=%v, s=%v, g=%v\n", proc.rusage.CompTime,
		proc.rusage.StreamTime, proc.rusage.GarbleTime)

	proc.ktracePrefix()
	fmt.Printf("RUSG g=%v, xor=%v, nxor=%v\n", proc.rusage.NumGates,
		proc.rusage.NumXOR, proc.rusage.NumNonXOR)
}
