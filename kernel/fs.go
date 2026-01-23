//
// Copyright (c) 2025-2026 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OpenFlag defines the flags for the open syscall.
type OpenFlag int32

// Flags for the open syscall.
const (
	ReadOnly  OpenFlag = 0x00000000
	WriteOnly OpenFlag = 0x00000001
	ReadWrite OpenFlag = 0x00000002
	Append    OpenFlag = 0x00000008
	Create    OpenFlag = 0x00000200
	Truncate  OpenFlag = 0x00000400
	Encrypt   OpenFlag = 0x01000000
)

const (
	// EncrFileMagic is the magic value for encrypted files.
	EncrFileMagic uint32 = 0x45464d01
)

var oflags = map[OpenFlag]string{
	WriteOnly: "O_WRONLY",
	ReadWrite: "O_RDWR",
	Append:    "O_APPEND",
	Create:    "O_CREAT",
	Truncate:  "O_TRUNC",
	Encrypt:   "O_ENCR",
}

func (f OpenFlag) String() string {
	if f == 0 {
		return "O_RDONLY"
	}
	var result string
	for i := 0; i < 32; i++ {
		flag := OpenFlag(1 << i)
		if f&flag != 0 {
			if len(result) > 0 {
				result += "|"
			}
			result += oflags[flag]
		}
	}
	return result
}

// FDFile implements file FDs.
type FDFile struct {
	f *os.File
}

// NewFileFD creates a new file FD.
func NewFileFD(f *os.File) *FD {
	return NewFD(&FDFile{
		f: f,
	})
}

// Close implements FD.Close.
func (fd *FDFile) Close() int {
	err := fd.f.Close()
	return int(mapError(err))
}

// Read implements FD.Read.
func (fd *FDFile) Read(b []byte) int {
	n, err := fd.f.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0
		}
		return int(mapError(err))
	}
	return n
}

// Write implements FD.Write.
func (fd *FDFile) Write(b []byte) int {
	n, err := fd.f.Write(b)
	if err != nil {
		return int(mapError(err))
	}
	return n
}

// MakePath creates a cleaned path from the path argument and the
// system state cwd, chroot, and root.
func (proc *Process) MakePath(path string) string {
	if path[0] != '/' {
		path = filepath.Join(proc.cwd, path)
	}
	path = filepath.Clean(path)
	return filepath.Join(proc.kern.params.Filesystem, proc.root, path)
}

// Chroot changes the process' root directory.
func (proc *Process) Chroot(path string) error {
	path = proc.MakePath(path)

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return Errno(ENOTDIR)
	}
	proc.root = path[len(proc.kern.params.Filesystem):]
	if strings.HasPrefix(path, proc.cwd) {
		proc.cwd = proc.cwd[len(path):]
	} else {
		proc.cwd = "/"
	}
	return nil
}

// FileInfo defines file information and is returned by the open
// syscall along with the file descriptor.
type FileInfo struct {
	Size      int64
	ModTime   time.Time
	BlockSize uint16
	Algorithm KeyType
	Flags     uint8
	PlainSize int64
	Nonce     [16]byte
}

// NewFileInfo constructs FileInfo from info and the optional file
// header.
func NewFileInfo(info os.FileInfo, hdr []byte) (*FileInfo, error) {
	fi := &FileInfo{
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	switch len(hdr) {
	case 0:
		return fi, nil

	case 28:
		magic := bo.Uint32(hdr[0:])
		if magic != EncrFileMagic {
			return nil, fmt.Errorf("invalid EncrFileMagic %08x", magic)
		}
		fi.BlockSize = bo.Uint16(hdr[4:])
		fi.Algorithm = KeyType(hdr[6])
		fi.Flags = hdr[7]
		fi.PlainSize = int64(bo.Uint64(hdr[8:]))
		copy(fi.Nonce[:], hdr[16:])

		return fi, nil

	default:
		return nil, fmt.Errorf("invalid encryption header length: %v", len(hdr))
	}
}

// Bytes return the serialized file info.
func (fi *FileInfo) Bytes() []byte {
	length := 16
	if fi.BlockSize != 0 {
		length += 16
	}
	buf := make([]byte, length)
	bo.PutUint64(buf[0:], uint64(fi.Size))
	bo.PutUint64(buf[8:], uint64(fi.ModTime.UnixMilli()))

	if fi.BlockSize != 0 {
		bo.PutUint16(buf[16:], fi.BlockSize)
		buf[18] = byte(fi.Algorithm)
		buf[19] = fi.Flags

		// The file's real size is irrelevant and depends on the
		// encryption header size, and encryption algorithm. Replace
		// the FileSize with the file's plaintext size.
		bo.PutUint64(buf[0:], uint64(fi.PlainSize))

		copy(buf[20:], fi.Nonce[:])
	}

	return buf
}
