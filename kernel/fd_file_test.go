//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
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
	for idx, test := range pathTests {
		path := MakePath(test.path, test.cwd, test.chroot, test.root)
		if path != test.result {
			t.Errorf("test%d: got %v, expected %v\n", idx, path, test.result)
		}
	}
}
