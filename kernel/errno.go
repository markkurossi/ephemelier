//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//
// The error numbers and their descriptions are taken from the NetBSD
// source code, from the errno.h file. The original copyright is as
// follows:

/*	$NetBSD: errno.h,v 1.42 2020/03/08 22:09:43 mgorny Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)errno.h	8.5 (Berkeley) 1/21/94
 */

package kernel

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strings"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

// Errno defines error numbers.
type Errno int32

// Error numbers.
const (
	EPERM           Errno = 1  /* Operation not permitted */
	ENOENT          Errno = 2  /* No such file or directory */
	ESRCH           Errno = 3  /* No such process */
	EINTR           Errno = 4  /* Interrupted system call */
	EIO             Errno = 5  /* Input/output error */
	ENXIO           Errno = 6  /* Device not configured */
	E2BIG           Errno = 7  /* Argument list too long */
	ENOEXEC         Errno = 8  /* Exec format error */
	EBADF           Errno = 9  /* Bad file descriptor */
	ECHILD          Errno = 10 /* No child processes */
	EDEADLK         Errno = 11 /* Resource deadlock avoided */
	ENOMEM          Errno = 12 /* Cannot allocate memory */
	EACCES          Errno = 13 /* Permission denied */
	EFAULT          Errno = 14 /* Bad address */
	ENOTBLK         Errno = 15 /* Block device required */
	EBUSY           Errno = 16 /* Device busy */
	EEXIST          Errno = 17 /* File exists */
	EXDEV           Errno = 18 /* Cross-device link */
	ENODEV          Errno = 19 /* Operation not supported by device */
	ENOTDIR         Errno = 20 /* Not a directory */
	EISDIR          Errno = 21 /* Is a directory */
	EINVAL          Errno = 22 /* Invalid argument */
	ENFILE          Errno = 23 /* Too many open files in system */
	EMFILE          Errno = 24 /* Too many open files */
	ENOTTY          Errno = 25 /* Inappropriate ioctl for device */
	ETXTBSY         Errno = 26 /* Text file busy */
	EFBIG           Errno = 27 /* File too large */
	ENOSPC          Errno = 28 /* No space left on device */
	ESPIPE          Errno = 29 /* Illegal seek */
	EROFS           Errno = 30 /* Read-only file system */
	EMLINK          Errno = 31 /* Too many links */
	EPIPE           Errno = 32 /* Broken pipe */
	EDOM            Errno = 33 /* Numerical argument out of domain */
	ERANGE          Errno = 34 /* Result too large or too small */
	EAGAIN          Errno = 35 /* Resource temporarily unavailable */
	EINPROGRESS     Errno = 36 /* Operation now in progress */
	EALREADY        Errno = 37 /* Operation already in progress */
	ENOTSOCK        Errno = 38 /* Socket operation on non-socket */
	EDESTADDRREQ    Errno = 39 /* Destination address required */
	EMSGSIZE        Errno = 40 /* Message too long */
	EPROTOTYPE      Errno = 41 /* Protocol wrong type for socket */
	ENOPROTOOPT     Errno = 42 /* Protocol option not available */
	EPROTONOSUPPORT Errno = 43 /* Protocol not supported */
	ESOCKTNOSUPPORT Errno = 44 /* Socket type not supported */
	EOPNOTSUPP      Errno = 45 /* Operation not supported */
	EPFNOSUPPORT    Errno = 46 /* Protocol family not supported */
	EAFNOSUPPORT    Errno = 47 /* Address family not supported by protocol family */
	EADDRINUSE      Errno = 48 /* Address already in use */
	EADDRNOTAVAIL   Errno = 49 /* Can't assign requested address */
	ENETDOWN        Errno = 50 /* Network is down */
	ENETUNREACH     Errno = 51 /* Network is unreachable */
	ENETRESET       Errno = 52 /* Network dropped connection on reset */
	ECONNABORTED    Errno = 53 /* Software caused connection abort */
	ECONNRESET      Errno = 54 /* Connection reset by peer */
	ENOBUFS         Errno = 55 /* No buffer space available */
	EISCONN         Errno = 56 /* Socket is already connected */
	ENOTCONN        Errno = 57 /* Socket is not connected */
	ESHUTDOWN       Errno = 58 /* Can't send after socket shutdown */
	ETOOMANYREFS    Errno = 59 /* Too many references: can't splice */
	ETIMEDOUT       Errno = 60 /* Operation timed out */
	ECONNREFUSED    Errno = 61 /* Connection refused */
	ELOOP           Errno = 62 /* Too many levels of symbolic links */
	ENAMETOOLONG    Errno = 63 /* File name too long */
	EHOSTDOWN       Errno = 64 /* Host is down */
	EHOSTUNREACH    Errno = 65 /* No route to host */
	ENOTEMPTY       Errno = 66 /* Directory not empty */
	EPROCLIM        Errno = 67 /* Too many processes */
	EUSERS          Errno = 68 /* Too many users */
	EDQUOT          Errno = 69 /* Disc quota exceeded */
	ESTALE          Errno = 70 /* Stale NFS file handle */
	EREMOTE         Errno = 71 /* Too many levels of remote in path */
	EBADRPC         Errno = 72 /* RPC struct is bad */
	ERPCMISMATCH    Errno = 73 /* RPC version wrong */
	EPROGUNAVAIL    Errno = 74 /* RPC prog. not avail */
	EPROGMISMATCH   Errno = 75 /* Program version wrong */
	EPROCUNAVAIL    Errno = 76 /* Bad procedure for program */
	ENOLCK          Errno = 77 /* No locks available */
	ENOSYS          Errno = 78 /* Function not implemented */
	EFTYPE          Errno = 79 /* Inappropriate file type or format */
	EAUTH           Errno = 80 /* Authentication error */
	ENEEDAUTH       Errno = 81 /* Need authenticator */
	EIDRM           Errno = 82 /* Identifier removed */
	ENOMSG          Errno = 83 /* No message of desired type */
	EOVERFLOW       Errno = 84 /* Value too large to be stored in data type */
	EILSEQ          Errno = 85 /* Illegal byte sequence */
	ENOTSUP         Errno = 86 /* Not supported */
	ECANCELED       Errno = 87 /* Operation canceled */
	EBADMSG         Errno = 88 /* Bad or Corrupt message */
	ENODATA         Errno = 89 /* No message available */
	ENOSR           Errno = 90 /* No STREAM resources */
	ENOSTR          Errno = 91 /* Not a STREAM */
	ETIME           Errno = 92 /* STREAM ioctl timeout */
	ENOATTR         Errno = 93 /* Attribute not found */
	EMULTIHOP       Errno = 94 /* Multihop attempted */
	ENOLINK         Errno = 95 /* Link has been severed */
	EPROTO          Errno = 96 /* Protocol error */
	EOWNERDEAD      Errno = 97 /* Previous owner died */
	ENOTRECOVERABLE Errno = 98 /* State not recoverable */
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
	EPERM:           "EPERM",
	ENOENT:          "ENOENT",
	ESRCH:           "ESRCH",
	EINTR:           "EINTR",
	EIO:             "EIO",
	ENXIO:           "ENXIO",
	E2BIG:           "E2BIG",
	ENOEXEC:         "ENOEXEC",
	EBADF:           "EBADF",
	ECHILD:          "ECHILD",
	EDEADLK:         "EDEADLK",
	ENOMEM:          "ENOMEM",
	EACCES:          "EACCES",
	EFAULT:          "EFAULT",
	ENOTBLK:         "ENOTBLK",
	EBUSY:           "EBUSY",
	EEXIST:          "EEXIST",
	EXDEV:           "EXDEV",
	ENODEV:          "ENODEV",
	ENOTDIR:         "ENOTDIR",
	EISDIR:          "EISDIR",
	EINVAL:          "EINVAL",
	ENFILE:          "ENFILE",
	EMFILE:          "EMFILE",
	ENOTTY:          "ENOTTY",
	ETXTBSY:         "ETXTBSY",
	EFBIG:           "EFBIG",
	ENOSPC:          "ENOSPC",
	ESPIPE:          "ESPIPE",
	EROFS:           "EROFS",
	EMLINK:          "EMLINK",
	EPIPE:           "EPIPE",
	EDOM:            "EDOM",
	ERANGE:          "ERANGE",
	EAGAIN:          "EAGAIN",
	EINPROGRESS:     "EINPROGRESS",
	EALREADY:        "EALREADY",
	ENOTSOCK:        "ENOTSOCK",
	EDESTADDRREQ:    "EDESTADDRREQ",
	EMSGSIZE:        "EMSGSIZE",
	EPROTOTYPE:      "EPROTOTYPE",
	ENOPROTOOPT:     "ENOPROTOOPT",
	EPROTONOSUPPORT: "EPROTONOSUPPORT",
	ESOCKTNOSUPPORT: "ESOCKTNOSUPPORT",
	EOPNOTSUPP:      "EOPNOTSUPP",
	EPFNOSUPPORT:    "EPFNOSUPPORT",
	EAFNOSUPPORT:    "EAFNOSUPPORT",
	EADDRINUSE:      "EADDRINUSE",
	EADDRNOTAVAIL:   "EADDRNOTAVAIL",
	ENETDOWN:        "ENETDOWN",
	ENETUNREACH:     "ENETUNREACH",
	ENETRESET:       "ENETRESET",
	ECONNABORTED:    "ECONNABORTED",
	ECONNRESET:      "ECONNRESET",
	ENOBUFS:         "ENOBUFS",
	EISCONN:         "EISCONN",
	ENOTCONN:        "ENOTCONN",
	ESHUTDOWN:       "ESHUTDOWN",
	ETOOMANYREFS:    "ETOOMANYREFS",
	ETIMEDOUT:       "ETIMEDOUT",
	ECONNREFUSED:    "ECONNREFUSED",
	ELOOP:           "ELOOP",
	ENAMETOOLONG:    "ENAMETOOLONG",
	EHOSTDOWN:       "EHOSTDOWN",
	EHOSTUNREACH:    "EHOSTUNREACH",
	ENOTEMPTY:       "ENOTEMPTY",
	EPROCLIM:        "EPROCLIM",
	EUSERS:          "EUSERS",
	EDQUOT:          "EDQUOT",
	ESTALE:          "ESTALE",
	EREMOTE:         "EREMOTE",
	EBADRPC:         "EBADRPC",
	ERPCMISMATCH:    "ERPCMISMATCH",
	EPROGUNAVAIL:    "EPROGUNAVAIL",
	EPROGMISMATCH:   "EPROGMISMATCH",
	EPROCUNAVAIL:    "EPROCUNAVAIL",
	ENOLCK:          "ENOLCK",
	ENOSYS:          "ENOSYS",
	EFTYPE:          "EFTYPE",
	EAUTH:           "EAUTH",
	ENEEDAUTH:       "ENEEDAUTH",
	EIDRM:           "EIDRM",
	ENOMSG:          "ENOMSG",
	EOVERFLOW:       "EOVERFLOW",
	EILSEQ:          "EILSEQ",
	ENOTSUP:         "ENOTSUP",
	ECANCELED:       "ECANCELED",
	EBADMSG:         "EBADMSG",
	ENODATA:         "ENODATA",
	ENOSR:           "ENOSR",
	ENOSTR:          "ENOSTR",
	ETIME:           "ETIME",
	ENOATTR:         "ENOATTR",
	EMULTIHOP:       "EMULTIHOP",
	ENOLINK:         "ENOLINK",
	EPROTO:          "EPROTO",
	EOWNERDEAD:      "EOWNERDEAD",
	ENOTRECOVERABLE: "ENOTRECOVERABLE",
}

var errnoDescriptions = map[Errno]string{
	EPERM:           "Operation not permitted",
	ENOENT:          "No such file or directory",
	ESRCH:           "No such process",
	EINTR:           "Interrupted system call",
	EIO:             "Input/output error",
	ENXIO:           "Device not configured",
	E2BIG:           "Argument list too long",
	ENOEXEC:         "Exec format error",
	EBADF:           "Bad file descriptor",
	ECHILD:          "No child processes",
	EDEADLK:         "Resource deadlock avoided",
	ENOMEM:          "Cannot allocate memory",
	EACCES:          "Permission denied",
	EFAULT:          "Bad address",
	ENOTBLK:         "Block device required",
	EBUSY:           "Device busy",
	EEXIST:          "File exists",
	EXDEV:           "Cross-device link",
	ENODEV:          "Operation not supported by device",
	ENOTDIR:         "Not a directory",
	EISDIR:          "Is a directory",
	EINVAL:          "Invalid argument",
	ENFILE:          "Too many open files in system",
	EMFILE:          "Too many open files",
	ENOTTY:          "Inappropriate ioctl for device",
	ETXTBSY:         "Text file busy",
	EFBIG:           "File too large",
	ENOSPC:          "No space left on device",
	ESPIPE:          "Illegal seek",
	EROFS:           "Read-only file system",
	EMLINK:          "Too many links",
	EPIPE:           "Broken pipe",
	EDOM:            "Numerical argument out of domain",
	ERANGE:          "Result too large or too small",
	EAGAIN:          "Resource temporarily unavailable",
	EINPROGRESS:     "Operation now in progress",
	EALREADY:        "Operation already in progress",
	ENOTSOCK:        "Socket operation on non-socket",
	EDESTADDRREQ:    "Destination address required",
	EMSGSIZE:        "Message too long",
	EPROTOTYPE:      "Protocol wrong type for socket",
	ENOPROTOOPT:     "Protocol option not available",
	EPROTONOSUPPORT: "Protocol not supported",
	ESOCKTNOSUPPORT: "Socket type not supported",
	EOPNOTSUPP:      "Operation not supported",
	EPFNOSUPPORT:    "Protocol family not supported",
	EAFNOSUPPORT:    "Address family not supported by protocol family",
	EADDRINUSE:      "Address already in use",
	EADDRNOTAVAIL:   "Can't assign requested address",
	ENETDOWN:        "Network is down",
	ENETUNREACH:     "Network is unreachable",
	ENETRESET:       "Network dropped connection on reset",
	ECONNABORTED:    "Software caused connection abort",
	ECONNRESET:      "Connection reset by peer",
	ENOBUFS:         "No buffer space available",
	EISCONN:         "Socket is already connected",
	ENOTCONN:        "Socket is not connected",
	ESHUTDOWN:       "Can't send after socket shutdown",
	ETOOMANYREFS:    "Too many references: can't splice",
	ETIMEDOUT:       "Operation timed out",
	ECONNREFUSED:    "Connection refused",
	ELOOP:           "Too many levels of symbolic links",
	ENAMETOOLONG:    "File name too long",
	EHOSTDOWN:       "Host is down",
	EHOSTUNREACH:    "No route to host",
	ENOTEMPTY:       "Directory not empty",
	EPROCLIM:        "Too many processes",
	EUSERS:          "Too many users",
	EDQUOT:          "Disc quota exceeded",
	ESTALE:          "Stale NFS file handle",
	EREMOTE:         "Too many levels of remote in path",
	EBADRPC:         "RPC struct is bad",
	ERPCMISMATCH:    "RPC version wrong",
	EPROGUNAVAIL:    "RPC prog. not avail",
	EPROGMISMATCH:   "Program version wrong",
	EPROCUNAVAIL:    "Bad procedure for program",
	ENOLCK:          "No locks available",
	ENOSYS:          "Function not implemented",
	EFTYPE:          "Inappropriate file type or format",
	EAUTH:           "Authentication error",
	ENEEDAUTH:       "Need authenticator",
	EIDRM:           "Identifier removed",
	ENOMSG:          "No message of desired type",
	EOVERFLOW:       "Value too large to be stored in data type",
	EILSEQ:          "Illegal byte sequence",
	ENOTSUP:         "Not supported",
	ECANCELED:       "Operation canceled",
	EBADMSG:         "Bad or Corrupt message",
	ENODATA:         "No message available",
	ENOSR:           "No STREAM resources",
	ENOSTR:          "Not a STREAM",
	ETIME:           "STREAM ioctl timeout",
	ENOATTR:         "Attribute not found",
	EMULTIHOP:       "Multihop attempted",
	ENOLINK:         "Link has been severed",
	EPROTO:          "Protocol error",
	EOWNERDEAD:      "Previous owner died",
	ENOTRECOVERABLE: "State not recoverable",
}

func mapError(err error) int {
	if err == nil {
		return 0
	}
	var perr *fs.PathError
	if errors.As(err, &perr) || errors.Is(err, io.EOF) {
		return int(-EBADF)
	}
	var tlsAlert tls.AlertDescription
	if errors.As(err, &tlsAlert) {
		errno, ok := tlsAlertToErrno[tlsAlert]
		if ok {
			return int(-errno)
		}
	}
	var netOpError *net.OpError
	if errors.As(err, &netOpError) {
		if false {
			fmt.Printf(" - Op    : %v\n", netOpError.Op)
			fmt.Printf(" - Net   : %v\n", netOpError.Net)
			fmt.Printf(" - Source: %v\n", netOpError.Source)
			fmt.Printf(" - Addr  : %v\n", netOpError.Addr)
			fmt.Printf(" - Err   : %v\n", netOpError.Err)
		}
		opError := netOpError.Error()
		if errors.Is(netOpError.Err, net.ErrClosed) {
			return int(-EBADF)
		} else if strings.Contains(opError, "connection reset by peer") {
			return int(-ECONNRESET)
		}
	}

	fmt.Printf("kernel : unknown error, defaulting to: %v\n", EINVAL)
	fmt.Printf(" - err : %v\n", err)
	fmt.Printf(" - type: %T\n", err)

	return int(-EINVAL)
}
