//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"fmt"
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
	SysWait
	SysGetrandom
	SysYield
	SysGetpid
)

// Port system calls.
const (
	SysGetport Syscall = iota + 100
	SysCreateport
	SysSendport
	SysRecvport
	SysCreateMsg
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
	SysGetpid:    "getpid",

	SysGetport:    "getport",
	SysCreateport: "createport",
	SysSendport:   "sendport",
	SysRecvport:   "recvport",
	SysCreateMsg:  "createmsg",
}
