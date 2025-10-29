//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"github.com/markkurossi/ephemelier/crypto/tls"
)

func (proc *Process) tlsServer(sys *syscall) {
	fd, ok := proc.fds[sys.arg0]
	if !ok {
		sys.SetArg0(int32(-EBADF))
		return
	}
	socketfd, ok := fd.Impl.(*FDSocket)
	if !ok {
		sys.SetArg0(int32(-ENOTSOCK))
		return
	}
	var err error
	if proc.role == RoleGarbler {
		err = proc.tlsServerGarbler(socketfd, sys)
	} else {
		err = proc.tlsServerEvaluator(socketfd, sys)
	}
	if err != nil {
		sys.SetArg0(int32(mapError(err)))
		return
	}
}

func (proc *Process) tlsServerGarbler(sock *FDSocket, sys *syscall) error {
	conn := tls.NewConnection(sock.conn)

	err := conn.ServerHandshake()
	if err != nil {
		return err
	}

	sys.SetArg0(-1)
	return nil
}

func (proc *Process) tlsServerEvaluator(sock *FDSocket, sys *syscall) error {
	sys.SetArg0(0)
	return nil
}
