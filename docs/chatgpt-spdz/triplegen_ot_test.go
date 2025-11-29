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

// reconstruct returns (x0 + x1) mod p
func reconstruct(x0, x1 *Share) *big.Int {
	sum := new(big.Int).Add(x0.V, x1.V)
	sum.Mod(sum, p256P)
	return sum
}

func TestGenerateBeaverTriplesOT(t *testing.T) {
	const tripleCount = 20
	const auditRate = 0.0 // disable auditing unless you want it

	// Build p2p pipe
	c0, c1 := p2p.Pipe()

	// Base OT instances (fresh per party)
	ot0 := ot.NewCO(rand.Reader)
	ot1 := ot.NewCO(rand.Reader)

	var triples0, triples1 []*Triple
	var err0, err1 error

	var wg sync.WaitGroup
	wg.Add(2)

	// Party 0
	go func() {
		defer wg.Done()
		triples0, err0 = GenerateBeaverTriplesOT(c0, ot0, 0, tripleCount, auditRate)
	}()

	// Party 1
	go func() {
		defer wg.Done()
		triples1, err1 = GenerateBeaverTriplesOT(c1, ot1, 1, tripleCount, auditRate)
	}()

	// Timeout guard
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout: deadlock in GenerateBeaverTriplesOT")
	}

	if err0 != nil {
		t.Fatalf("party 0 error: %v", err0)
	}
	if err1 != nil {
		t.Fatalf("party 1 error: %v", err1)
	}

	// Validate triples
	if len(triples0) != tripleCount || len(triples1) != tripleCount {
		t.Fatalf("wrong triple count returned")
	}

	for i := 0; i < tripleCount; i++ {
		A := reconstruct(triples0[i].A, triples1[i].A)
		B := reconstruct(triples0[i].B, triples1[i].B)
		C := reconstruct(triples0[i].C, triples1[i].C)

		want := new(big.Int).Mul(A, B)
		want.Mod(want, p256P)

		if C.Cmp(want) != 0 {
			t.Fatalf("triple %d mismatch:\n"+
				"  A = %x\n  B = %x\n  C = %x\n  want = %x\n",
				i, A, B, C, want)
		}
	}
}
