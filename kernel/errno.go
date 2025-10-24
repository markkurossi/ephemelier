//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// Errno defines error numbers.
type Errno int32

// Error numbers.
const (
	ENOENT          Errno = 2
	EBADF           Errno = 9
	ECHILD          Errno = 10
	EFAULT          Errno = 14
	EINVAL          Errno = 22
	ERANGE          Errno = 34
	ENOTSOCK        Errno = 38
	EPROTONOSUPPORT Errno = 43
	EAFNOSUPPORT    Errno = 47
)

func (err Errno) String() string {
	name, ok := errnoNames[err]
	if ok {
		desc, ok := errnoDescriptions[err]
		if ok {
			return name + " " + desc
		}
		return name
	}
	return fmt.Sprintf("{Errno %d}", err)
}

// Description returns a short description about the error code.
func (err Errno) Description() string {
	desc, ok := errnoDescriptions[err]
	if ok {
		return desc
	}
	return fmt.Sprintf("{Errno %d}", err)
}

var errnoNames = map[Errno]string{
	ENOENT:          "ENOENT",
	EBADF:           "EBADF",
	ECHILD:          "ECHILD",
	EFAULT:          "EFAULT",
	EINVAL:          "EINVAL",
	ERANGE:          "ERANGE",
	ENOTSOCK:        "ENOTSOCK",
	EPROTONOSUPPORT: "EPROTONOSUPPORT",
	EAFNOSUPPORT:    "EAFNOSUPPORT",
}

var errnoDescriptions = map[Errno]string{
	ENOENT:          "No such file or directory",
	EBADF:           "Bad file descriptor",
	ECHILD:          "No child processes",
	EFAULT:          "Bad address",
	EINVAL:          "Invalid argument",
	ERANGE:          "Numerical result out of range",
	ENOTSOCK:        "Socket operation on non-socket",
	EPROTONOSUPPORT: "Protocol not supported",
	EAFNOSUPPORT:    "Address family not supported by protocol family",
}

func mapError(err error) int {
	if err == nil {
		return 0
	}
	var perr *fs.PathError
	if errors.As(err, &perr) || errors.Is(err, io.EOF) {
		return int(-EBADF)
	}
	fmt.Printf("error %v not handled, defaulting to %v\n", err, EINVAL)
	return int(-EINVAL)
}
