package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// curveAdd:
//  - g.X: bb32c4722cbd5a05510cfbb9c4c152f144e70fa24b9e428b9b3bf9f39dd43bbe
//  - g.Y: 25b7f3d9d79e5ca057b0ba7a940d5c917d41cc0a08d41cb1b2b83905e795c7db
//  - e.X: 7aaf9286743dc0adbd8fa93d305521cf0f62947ee5831bc8e355b133de65bd5a
//  - e.Y: 5e183e2d1f66256cc42883de880fdc7c177e99f2e003a2dd298e458aaebcc799
//  =>  X: 72ebc952286e5b3956525ea0cf2a055ab6ec01ad840da4330714dd5578d6e76a
//  =>  Y: 8aaff44f299ad260e21c9ff30885a69ff11cede1d9e7786d32e40080ec95c253

var (
	Curve  = elliptic.P256()
	P      = Curve.Params().P
	mod256 = new(big.Int).Lsh(big.NewInt(1), 256)
)

func main() {

	gr, ew := io.Pipe()
	er, gw := io.Pipe()

	gio := newReadWriter(gr, gw)
	eio := newReadWriter(er, ew)

	var wg sync.WaitGroup
	var oti = ot.NewCO(rand.Reader)

	var ex, ey, exi, eyi *big.Int

	wg.Go(func() {
		var okx, oky bool
		exi, okx = new(big.Int).SetString("7aaf9286743dc0adbd8fa93d305521cf0f62947ee5831bc8e355b133de65bd5a", 16)
		eyi, oky = new(big.Int).SetString("5e183e2d1f66256cc42883de880fdc7c177e99f2e003a2dd298e458aaebcc799", 16)
		if !(okx && oky) {
			panic("e")
		}
		var err error
		ex, ey, err = Peer(oti, 1, p2p.NewConn(eio), exi, eyi)
		if err != nil {
			panic(err)
		}
	})

	gxi, okx := new(big.Int).SetString("bb32c4722cbd5a05510cfbb9c4c152f144e70fa24b9e428b9b3bf9f39dd43bbe", 16)
	gyi, oky := new(big.Int).SetString("25b7f3d9d79e5ca057b0ba7a940d5c917d41cc0a08d41cb1b2b83905e795c7db", 16)
	if !(okx && oky) {
		panic("g")
	}

	gx, gy, err := Peer(oti, 0, p2p.NewConn(gio), gxi, gyi)
	if err != nil {
		panic(err)
	}

	wg.Wait()

	rx := add(gx, ex)
	ry := add(gy, ey)

	fmt.Printf("rx: %v\n", rx.Text(16))
	fmt.Printf("ry: %v\n", ry.Text(16))

	xx, yy := Curve.Add(exi, eyi, gxi, gyi)

	fmt.Printf("xx: %v\n", xx.Text(16))
	fmt.Printf("yy: %v\n", yy.Text(16))
}

func add(x, y *big.Int) *big.Int {
	r := new(big.Int).Add(x, y)

	return new(big.Int).Mod(r, mod256)
}

func newReadWriter(in io.Reader, out io.Writer) io.ReadWriter {
	return &wrap{
		in:  in,
		out: out,
	}
}

type wrap struct {
	in  io.Reader
	out io.Writer
}

func (w *wrap) Read(p []byte) (n int, err error) {
	return w.in.Read(p)
}

func (w *wrap) Write(p []byte) (n int, err error) {
	return w.out.Write(p)
}
