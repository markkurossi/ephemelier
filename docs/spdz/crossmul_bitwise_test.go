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

// --- helper: random field element ---
func randField() *big.Int {
	x, err := randomFieldElement(rand.Reader)
	if err != nil {
		panic(err)
	}
	return x
}

// --- TestCrossMultiplyViaOT ---
func TestCrossMultiplyViaOT(t *testing.T) {
	const trials = 10

	for trial := 0; trial < trials; trial++ {

		// random a,b in the field
		a := randField()
		b := randField()

		// secret-share a = a0 + a1, b = b0 + b1
		a0 := randField()
		a1 := new(big.Int).Sub(a, a0)
		a1.Mod(a1, p256P)

		b0 := randField()
		b1 := new(big.Int).Sub(b, b0)
		b1.Mod(b1, p256P)

		// Create two ends of a Pipe()
		c0, c1 := p2p.Pipe()

		// Same OT type you use in SPDZ
		ot0 := ot.NewCO(rand.Reader)
		ot1 := ot.NewCO(rand.Reader)

		var wg sync.WaitGroup
		wg.Add(2)

		var cShare0, cShare1 *Share
		var err0, err1 error

		// Peer 0
		go func() {
			defer wg.Done()
			ssA := NewShare(a0)
			ssB := NewShare(b0)
			cShare0, err0 = CrossMultiplyViaOT(c0, ot0, 0, ssA, ssB)
		}()

		// Peer 1
		go func() {
			defer wg.Done()
			ssA := NewShare(a1)
			ssB := NewShare(b1)
			cShare1, err1 = CrossMultiplyViaOT(c1, ot1, 1, ssA, ssB)
		}()

		// Timeout to detect deadlocks
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// good
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout during CrossMultiplyViaOT trial %d", trial)
		}

		if err0 != nil {
			t.Fatalf("peer0 error: %v", err0)
		}
		if err1 != nil {
			t.Fatalf("peer1 error: %v", err1)
		}

		// reconstruct product
		c0v := cShare0.V
		c1v := cShare1.V

		c := new(big.Int).Add(c0v, c1v)
		c.Mod(c, p256P)

		want := new(big.Int).Mul(a, b)
		want.Mod(want, p256P)

		if c.Cmp(want) != 0 {
			t.Fatalf("trial %d: wrong product\n"+
				"a=%x\nb=%x\nc=%x\nwant=%x\n",
				trial, a, b, c, want)
		}
	}
}
