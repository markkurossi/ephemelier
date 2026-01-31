//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"fmt"
	"testing"
)

var mapErrorTests = []struct {
	err   error
	errno int32
}{
	{
		err:   EAUTH,
		errno: int32(-EAUTH),
	},
	{
		err:   fmt.Errorf("invalid EncrFileMagic %08x: %w", 0, ENOEXEC),
		errno: int32(-ENOEXEC),
	},
}

func TestMapError(t *testing.T) {
	for i, test := range mapErrorTests {
		mapped := mapError(test.err)
		if mapped != test.errno {
			t.Errorf("test-%v: mapError(%v)=%v, expected %v\n",
				i, test.err, mapped, test.errno)
		}
	}
}
