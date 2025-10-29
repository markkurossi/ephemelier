//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"testing"
)

func TestHandshakeType(t *testing.T) {
	if HTNewSessionTicket != 4 {
		t.Errorf("HTNewSessionTicket=%v, expected 4\n", HTNewSessionTicket)
	}
	if HTFinished != 20 {
		t.Errorf("HTFinished=%v, expected 20\n", HTFinished)
	}
}
