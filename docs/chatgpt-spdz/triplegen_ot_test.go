package main

import (
	"crypto/rand"
	"math/big"
	"sync"
	"testing"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

func TestOTTripleGen(t *testing.T) {
	c0, c1 := p2p.Pipe()
	oti0 := ot.NewCO(rand.Reader)
	oti1 := ot.NewCO(rand.Reader)

	const N = 50

	var wg sync.WaitGroup
	wg.Add(2)

	var triples0, triples1 []*Triple

	go func() {
		defer wg.Done()
		tr, err := GenerateBeaverTriplesOT(c0, oti0, 0, N, 0)
		if err != nil {
			t.Fatal(err)
		}
		triples0 = tr
	}()

	go func() {
		defer wg.Done()
		tr, err := GenerateBeaverTriplesOT(c1, oti1, 1, N, 0)
		if err != nil {
			t.Fatal(err)
		}
		triples1 = tr
	}()

	wg.Wait()

	// Spot check correctness
	for i := 0; i < N; i++ {
		a := new(big.Int).Add(triples0[i].A.V, triples1[i].A.V)
		b := new(big.Int).Add(triples0[i].B.V, triples1[i].B.V)
		c := new(big.Int).Add(triples0[i].C.V, triples1[i].C.V)
		a.Mod(a, p256P)
		b.Mod(b, p256P)
		c.Mod(c, p256P)

		want := new(big.Int).Mul(a, b)
		want.Mod(want, p256P)
		if c.Cmp(want) != 0 {
			t.Fatalf("triple %d incorrect: got %v want %v", i, c, want)
		}
	}
}
