//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package spdz

import (
	"crypto/rand"
	"math/big"
	"sync"
	"testing"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var wellKnown = []struct {
	gx string
	gy string
	ex string
	ey string
	rx string
	ry string
}{
	{
		gx: "bb32c4722cbd5a05510cfbb9c4c152f144e70fa24b9e428b9b3bf9f39dd43bbe",
		gy: "25b7f3d9d79e5ca057b0ba7a940d5c917d41cc0a08d41cb1b2b83905e795c7db",
		ex: "7aaf9286743dc0adbd8fa93d305521cf0f62947ee5831bc8e355b133de65bd5a",
		ey: "5e183e2d1f66256cc42883de880fdc7c177e99f2e003a2dd298e458aaebcc799",
		rx: "72ebc952286e5b3956525ea0cf2a055ab6ec01ad840da4330714dd5578d6e76a",
		ry: "8aaff44f299ad260e21c9ff30885a69ff11cede1d9e7786d32e40080ec95c253",
	},
}

func TestP256WellKnown(t *testing.T) {
	for _, test := range wellKnown {
		gx, ok := new(big.Int).SetString(test.gx, 16)
		if !ok {
			t.Fatalf("invalid gx")
		}
		gy, ok := new(big.Int).SetString(test.gy, 16)
		if !ok {
			t.Fatalf("invalid gy")
		}
		ex, ok := new(big.Int).SetString(test.ex, 16)
		if !ok {
			t.Fatalf("invalid ex")
		}
		ey, ok := new(big.Int).SetString(test.ey, 16)
		if !ok {
			t.Fatalf("invalid ey")
		}
		rx, ok := new(big.Int).SetString(test.rx, 16)
		if !ok {
			t.Fatalf("invalid rx")
		}
		ry, ok := new(big.Int).SetString(test.ry, 16)
		if !ok {
			t.Fatalf("invalid ry")
		}

		testAdd(t, gx, gy, ex, ey, rx, ry)
	}
}

func testAdd(t *testing.T, gx, gy, ex, ey, rx, ry *big.Int) {

	gConn, eConn := p2p.Pipe()
	var wg sync.WaitGroup

	var eErr error
	var rex, rey *big.Int

	wg.Go(func() {
		rex, rey, eErr = Peer(ot.NewCO(rand.Reader), 1, eConn, ex, ey)
	})

	rgx, rgy, err := Peer(ot.NewCO(rand.Reader), 0, gConn, gx, gy)
	if err != nil {
		t.Fatalf("garbler failed: %v", err)
	}

	wg.Wait()

	if eErr != nil {
		t.Fatalf("evaluator failed: %v", err)
	}

	crx := add(rgx, rex)
	cry := add(rgy, rey)

	if crx.Cmp(rx) != 0 {
		t.Errorf("computed x mismatch: %s != %s", crx.Text(16), rx.Text(16))
	}
	if cry.Cmp(ry) != 0 {
		t.Errorf("computed y mismatch: %s != %s", cry.Text(16), ry.Text(16))
	}

}

func TestRandomPoints(t *testing.T) {
	for i := 0; i < 5; i++ {
		gx, gy, err := randomPoint()
		if err != nil {
			t.Fatal(err)
		}
		ex, ey, err := randomPoint()
		if err != nil {
			t.Fatal(err)
		}
		rx, ry := curve.Add(gx, gy, ex, ey)

		testAdd(t, gx, gy, ex, ey, rx, ry)
	}
}

func randomPoint() (*big.Int, *big.Int, error) {
	r, err := rand.Int(rand.Reader, curveParams.N)
	if err != nil {
		return nil, nil, err
	}

	x, y := curve.ScalarBaseMult(r.Bytes())
	return x, y, nil
}

func add(x, y *big.Int) *big.Int {
	r := new(big.Int).Add(x, y)
	return new(big.Int).Mod(r, p256P)
}
