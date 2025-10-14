//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

// Errno defines error numbers.
type Errno int32

// Error numbers.
const (
	ENOENT Errno = 2
	EBADF  Errno = 9
	ECHILD Errno = 10
	EINVAL Errno = 22
	ERANGE Errno = 34
)
