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
	SysDial
	SysListen
	SysAccept
	SysWait
	SysGetrandom
	SysTlsserver
	SysTlsclient
	SysTlshs
	SysTlsstatus
	SysContinue
	SysYield
	SysNext
	SysGetpid
)

// Port system calls.
const (
	SysGetport Syscall = iota + 100
	SysCreateport
	SysSendfd
	SysRecvfd
	SysCreatemsg
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
	SysDial:      "dial",
	SysListen:    "listen",
	SysAccept:    "accept",
	SysWait:      "wait",
	SysGetrandom: "getrandom",
	SysTlsserver: "tlsserver",
	SysTlsclient: "tlsclient",
	SysTlshs:     "tlshs",
	SysTlsstatus: "tlsstatus",
	SysContinue:  "continue",
	SysYield:     "yield",
	SysNext:      "next",
	SysGetpid:    "getpid",

	SysGetport:    "getport",
	SysCreateport: "createport",
	SysSendfd:     "sendfd",
	SysRecvfd:     "recvfd",
	SysCreatemsg:  "createmsg",
}
