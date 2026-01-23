//
// Copyright (c) 2025, 2026 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"fmt"
	"testing"
)

var pathTests = []struct {
	path   string
	cwd    string
	chroot string
	root   string
	result string
}{
	{
		path:   "motd",
		cwd:    "/",
		chroot: "/",
		root:   "fs",
		result: "fs/motd",
	},
	{
		path:   "../motd",
		cwd:    "/",
		chroot: "/",
		root:   "fs",
		result: "fs/motd",
	},
	{
		path:   "motd",
		cwd:    "/",
		chroot: "/etc/httpd/",
		root:   "fs",
		result: "fs/etc/httpd/motd",
	},
	{
		path:   "../../../motd",
		cwd:    "/",
		chroot: "/etc/httpd/",
		root:   "fs",
		result: "fs/etc/httpd/motd",
	},
	{
		path:   "motd",
		cwd:    "/static",
		chroot: "/etc/httpd/",
		root:   "fs",
		result: "fs/etc/httpd/static/motd",
	},
	{
		path:   "./motd",
		cwd:    "/static",
		chroot: "/etc/httpd/",
		root:   "fs",
		result: "fs/etc/httpd/static/motd",
	},
	{
		path:   "/motd",
		cwd:    "/static",
		chroot: "/etc/httpd/",
		root:   "fs",
		result: "fs/etc/httpd/motd",
	},
	{
		path:   "../../motd",
		cwd:    "/static",
		chroot: "/etc/httpd/",
		root:   "fs",
		result: "fs/etc/httpd/motd",
	},
}

func TestPaths(t *testing.T) {
	var kern Kernel

	proc := &Process{
		kern: &kern,
	}

	for idx, test := range pathTests {
		proc.cwd = test.cwd
		proc.root = test.chroot
		kern.params.Filesystem = test.root

		path := proc.MakePath(test.path)
		if path != test.result {
			t.Errorf("test%d: got %v, expected %v\n", idx, path, test.result)
		}
	}
}

func TestOpenFlags(t *testing.T) {
	fmt.Printf("0x601 = %v\n", OpenFlag(0x601))
}
