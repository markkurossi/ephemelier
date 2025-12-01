package main

import (
	"crypto/rand"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// reconstruct sum of two shares
func rec2(x0, x1 *Share) *big.Int {
	s := new(big.Int).Add(x0.V, x1.V)
	s.Mod(s, p256P)
	return s
}

func TestGenerateBeaverTriplesOTBatch(t *testing.T) {
	const tripleCount = 30
	const auditRate = 0.0 // set >0 to test auditing

	// Pipe connection between both peers
	c0, c1 := p2p.Pipe()

	// Base OT instances
	ot0 := ot.NewCO(rand.Reader)
	ot1 := ot.NewCO(rand.Reader)

	var triples0, triples1 []*Triple
	var err0, err1 error

	var wg sync.WaitGroup
	wg.Add(2)

	// Peer 0
	go func() {
		defer wg.Done()
		triples0, err0 = GenerateBeaverTriplesOTBatch(c0, ot0, 0, tripleCount, auditRate)
	}()

	// Peer 1
	go func() {
		defer wg.Done()
		triples1, err1 = GenerateBeaverTriplesOTBatch(c1, ot1, 1, tripleCount, auditRate)
	}()

	// Timeout watchdog
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout: likely deadlock in GenerateBeaverTriplesOTBatch")
	}

	if err0 != nil {
		t.Fatalf("peer0 error: %v", err0)
	}
	if err1 != nil {
		t.Fatalf("peer1 error: %v", err1)
	}

	if len(triples0) != tripleCount || len(triples1) != tripleCount {
		t.Fatalf("wrong number of triples returned")
	}

	// Validate triples
	for i := 0; i < tripleCount; i++ {
		A := rec2(triples0[i].A, triples1[i].A)
		B := rec2(triples0[i].B, triples1[i].B)
		C := rec2(triples0[i].C, triples1[i].C)

		want := new(big.Int).Mul(A, B)
		want.Mod(want, p256P)

		if C.Cmp(want) != 0 {
			t.Fatalf("triple %d incorrect:\nA=%x\nB=%x\nC=%x\nwant=%x\n",
				i, A, B, C, want)
		}
	}
}
