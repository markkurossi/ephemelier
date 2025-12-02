//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

// Package spdz implements the SPDZ protocol for P-256 point addtion.
package spdz

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var (
	curve       = elliptic.P256()
	curveParams = curve.Params()
	p256P       = curveParams.P
	p256N       = curveParams.N
)

// ---------- Helpers ----------

func modReduce(x *big.Int) *big.Int {
	z := new(big.Int).Mod(x, p256P)
	if z.Sign() < 0 {
		z.Add(z, p256P)
	}
	return z
}

func randomFieldElement(r io.Reader) (*big.Int, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return modReduce(new(big.Int).SetBytes(b)), nil
}

func bytes32(v *big.Int) []byte {
	b := make([]byte, 32)
	if v == nil {
		return b
	}
	z := modReduce(v)
	copy(b[32-len(z.Bytes()):], z.Bytes())
	return b
}

func read32ToBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func sendField(conn *p2p.Conn, v *big.Int) error {
	return conn.SendData(bytes32(v))
}

func recvField(conn *p2p.Conn) (*big.Int, error) {
	b, err := conn.ReceiveData()
	if err != nil {
		return nil, err
	}
	return read32ToBig(b), nil
}

// ---------- Share & Triple ----------

type Share struct {
	V *big.Int
}

func NewShare(v *big.Int) *Share {
	return &Share{V: modReduce(v)}
}

func AddShare(a, b *Share) *Share {
	z := new(big.Int).Add(a.V, b.V)
	return NewShare(z)
}

func SubShare(a, b *Share) *Share {
	z := new(big.Int).Sub(a.V, b.V)
	return NewShare(z)
}

type Triple struct {
	A *Share
	B *Share
	C *Share
}

// ---------- Beaver triple (dealer) ----------

// GenerateBeaverTriplesDealer: peer 0 is dealer. Produces `n` triples.
// Dealer samples global a,b, computes c = a*b mod p, then splits into additive shares:
//   - peer0 receives (a0,b0,c0) random
//   - peer1 receives (a1,b1,c1) = (a-a0, b-b0, c-c0)
func GenerateBeaverTriplesDealer(conn *p2p.Conn, oti ot.OT, id int, n int) ([]*Triple, error) {
	triples := make([]*Triple, n)
	if id == 0 {
		for i := 0; i < n; i++ {
			// global a,b
			aGlob, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}
			bGlob, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}
			cGlob := new(big.Int).Mod(new(big.Int).Mul(aGlob, bGlob), p256P)

			// local (peer0) random shares
			a0, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}
			b0, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}
			c0, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}

			// peer1 shares = global - local
			a1 := new(big.Int).Sub(aGlob, a0)
			a1.Mod(a1, p256P)
			b1 := new(big.Int).Sub(bGlob, b0)
			b1.Mod(b1, p256P)
			c1 := new(big.Int).Sub(cGlob, c0)
			c1.Mod(c1, p256P)

			// send peer1 shares
			if err := sendField(conn, a1); err != nil {
				return nil, err
			}
			if err := sendField(conn, b1); err != nil {
				return nil, err
			}
			if err := sendField(conn, c1); err != nil {
				return nil, err
			}
			if err := conn.Flush(); err != nil {
				return nil, err
			}

			triples[i] = &Triple{A: NewShare(a0), B: NewShare(b0), C: NewShare(c0)}
		}
	} else {
		for i := 0; i < n; i++ {
			a1, err := recvField(conn)
			if err != nil {
				return nil, err
			}
			b1, err := recvField(conn)
			if err != nil {
				return nil, err
			}
			c1, err := recvField(conn)
			if err != nil {
				return nil, err
			}
			triples[i] = &Triple{A: NewShare(a1), B: NewShare(b1), C: NewShare(c1)}
		}
	}
	return triples, nil
}

// ---------- Opening helpers ----------

// openShare: asymmetric ordering to avoid deadlock
func openShare(conn *p2p.Conn, id int, s *Share) (*big.Int, error) {
	if id == 0 {
		if err := sendField(conn, s.V); err != nil {
			return nil, err
		}
		if err := conn.Flush(); err != nil {
			return nil, err
		}
		peer, err := recvField(conn)
		if err != nil {
			return nil, err
		}
		sum := new(big.Int).Add(s.V, peer)
		return modReduce(sum), nil
	} else {
		peer, err := recvField(conn)
		if err != nil {
			return nil, err
		}
		if err := sendField(conn, s.V); err != nil {
			return nil, err
		}
		if err := conn.Flush(); err != nil {
			return nil, err
		}
		sum := new(big.Int).Add(s.V, peer)
		return modReduce(sum), nil
	}
}

// openTwoShares opens two shares in one round-trip
func openTwoShares(conn *p2p.Conn, id int, s1, s2 *Share) (*big.Int, *big.Int, error) {
	if id == 0 {
		if err := sendField(conn, s1.V); err != nil {
			return nil, nil, err
		}
		if err := sendField(conn, s2.V); err != nil {
			return nil, nil, err
		}
		if err := conn.Flush(); err != nil {
			return nil, nil, err
		}
		p1, err := recvField(conn)
		if err != nil {
			return nil, nil, err
		}
		p2, err := recvField(conn)
		if err != nil {
			return nil, nil, err
		}
		sum1 := modReduce(new(big.Int).Add(s1.V, p1))
		sum2 := modReduce(new(big.Int).Add(s2.V, p2))
		return sum1, sum2, nil
	} else {
		p1, err := recvField(conn)
		if err != nil {
			return nil, nil, err
		}
		p2, err := recvField(conn)
		if err != nil {
			return nil, nil, err
		}
		if err := sendField(conn, s1.V); err != nil {
			return nil, nil, err
		}
		if err := sendField(conn, s2.V); err != nil {
			return nil, nil, err
		}
		if err := conn.Flush(); err != nil {
			return nil, nil, err
		}
		sum1 := modReduce(new(big.Int).Add(s1.V, p1))
		sum2 := modReduce(new(big.Int).Add(s2.V, p2))
		return sum1, sum2, nil
	}
}

// ---------- Beaver multiplication (MulShare) ----------

// MulShare computes a*b given shares and a Beaver triple.
// Note: to avoid doubling d*e term, only one party (id==0) adds dv*ev.
func MulShare(conn *p2p.Conn, id int, a, b *Share, triple *Triple) (*Share, error) {
	d := SubShare(a, triple.A)
	e := SubShare(b, triple.B)

	dv, ev, err := openTwoShares(conn, id, d, e)
	if err != nil {
		return nil, err
	}

	term := new(big.Int).Set(triple.C.V)
	tmp := new(big.Int).Mul(dv, triple.B.V)
	term.Add(term, tmp)
	tmp2 := new(big.Int).Mul(ev, triple.A.V)
	term.Add(term, tmp2)
	if id == 0 {
		tmp3 := new(big.Int).Mul(dv, ev)
		term.Add(term, tmp3)
	}
	term.Mod(term, p256P)

	return NewShare(term), nil
}

// ---------- safeMul wrapper ----------

func safeMul(conn *p2p.Conn, id int, a, b *Share, triples []*Triple, tripleIndex *int) (*Share, error) {
	if *tripleIndex >= len(triples) {
		return nil, errors.New("not enough triples for multiplication")
	}
	t := triples[*tripleIndex]
	res, err := MulShare(conn, id, a, b, t)
	if err != nil {
		return nil, err
	}
	*tripleIndex++
	return res, nil
}

// ---------- ExpShare / InvShare (production) ----------

// ExpShare computes [x]^exponent (exponent is public) using square-and-multiply.
// It uses Beaver triples provided in 'triples' and advances tripleIndex accordingly.
func ExpShare(conn *p2p.Conn, id int, x *Share, exponent *big.Int, triples []*Triple, tripleIndex *int) (*Share, error) {
	// Initialize [res] = 1 additive share (peer0 holds 1, peer1 holds 0).
	var res *Share
	if id == 0 {
		res = NewShare(big.NewInt(1))
	} else {
		res = NewShare(big.NewInt(0))
	}

	// base copy
	base := NewShare(new(big.Int).Set(x.V))

	if exponent == nil {
		return nil, errors.New("nil exponent")
	}
	if exponent.Sign() == 0 {
		return res, nil
	}

	// Square-and-multiply (left-to-right)
	bitLen := exponent.BitLen()
	for i := bitLen - 1; i >= 0; i-- {
		// square
		var err error
		res, err = safeMul(conn, id, res, res, triples, tripleIndex)
		if err != nil {
			return nil, err
		}
		// if bit set, multiply by base
		if exponent.Bit(i) == 1 {
			res, err = safeMul(conn, id, res, base, triples, tripleIndex)
			if err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

// InvShare computes multiplicative inverse via Fermat: x^(p-2)
func InvShare(conn *p2p.Conn, id int, x *Share, triples []*Triple, tripleIndex *int) (*Share, error) {
	exp := new(big.Int).Sub(p256P, big.NewInt(2))
	return ExpShare(conn, id, x, exp, triples, tripleIndex)
}

// ---------- SPDZ point addition ----------

func SPDZPointAdd(conn *p2p.Conn, id int, x1, y1, x2, y2 *Share, triples []*Triple, tripleIndex *int) (*Share, *Share, error) {
	// dx = x2 - x1 ; dy = y2 - y1
	dx := SubShare(x2, x1)
	dy := SubShare(y2, y1)

	// invDx = inv(dx) inside MPC
	invDx, err := InvShare(conn, id, dx, triples, tripleIndex)
	if err != nil {
		return nil, nil, err
	}

	// lam = dy * invDx
	if *tripleIndex >= len(triples) {
		return nil, nil, errors.New("not enough triples for lam")
	}
	lam, err := MulShare(conn, id, dy, invDx, triples[*tripleIndex])
	if err != nil {
		return nil, nil, err
	}
	*tripleIndex++

	// lam2 = lam * lam
	if *tripleIndex >= len(triples) {
		return nil, nil, errors.New("not enough triples for lam2")
	}
	lam2, err := MulShare(conn, id, lam, lam, triples[*tripleIndex])
	if err != nil {
		return nil, nil, err
	}
	*tripleIndex++

	// x3 = lam2 - x1 - x2
	tmp := SubShare(lam2, x1)
	x3 := SubShare(tmp, x2)

	// y3 = lam*(x1 - x3) - y1
	diff := SubShare(x1, x3)
	if *tripleIndex >= len(triples) {
		return nil, nil, errors.New("not enough triples for lam*diff")
	}
	prod, err := MulShare(conn, id, lam, diff, triples[*tripleIndex])
	if err != nil {
		return nil, nil, err
	}
	*tripleIndex++
	y3 := SubShare(prod, y1)

	return x3, y3, nil
}

// ---------- Input sharing ----------

// ShareInput: owner==true => mask with random s and send o = val - s to peer; return local s.
// owner==false => receive o and use as local share.
func ShareInput(conn *p2p.Conn, id int, owner bool, val *big.Int) (*Share, error) {
	if owner {
		s, err := randomFieldElement(rand.Reader)
		if err != nil {
			return nil, err
		}
		o := new(big.Int).Sub(modReduce(val), s)
		o.Mod(o, p256P)
		if err := sendField(conn, o); err != nil {
			return nil, err
		}
		if err := conn.Flush(); err != nil {
			return nil, err
		}
		return NewShare(s), nil
	} else {
		o, err := recvField(conn)
		if err != nil {
			return nil, err
		}
		return NewShare(o), nil
	}
}

// ---------- Peer (top-level) ----------

// Peer(oti, id, conn, xInput, yInput) : each peer supplies only its own point.
// - If id==0, (xInput,yInput) is P; if id==1, (xInput,yInput) is Q.
func Peer(oti ot.OT, id int, conn *p2p.Conn, xInput, yInput *big.Int) (xOut, yOut *big.Int, err error) {
	if id != 0 && id != 1 {
		return nil, nil, errors.New("id must be 0 or 1")
	}

	// Init OT roles if needed
	if id == 0 {
		if err := oti.InitSender(conn); err != nil {
			return nil, nil, err
		}
	} else {
		if err := oti.InitReceiver(conn); err != nil {
			return nil, nil, err
		}
	}

	// Share inputs
	isOwnerP := (id == 0)
	isOwnerQ := (id == 1)

	x1Share, err := ShareInput(conn, id, isOwnerP, xInput)
	if err != nil {
		return nil, nil, err
	}
	y1Share, err := ShareInput(conn, id, isOwnerP, yInput)
	if err != nil {
		return nil, nil, err
	}
	x2Share, err := ShareInput(conn, id, isOwnerQ, xInput)
	if err != nil {
		return nil, nil, err
	}
	y2Share, err := ShareInput(conn, id, isOwnerQ, yInput)
	if err != nil {
		return nil, nil, err
	}

	// Generate Beaver triples (dealer = peer 0)
	triplesNeeded := 1400 // safe upper bound for inversion + intermediate multiplications
	triples, err := GenerateBeaverTriplesOTBatch(conn, oti, id, triplesNeeded, 0)
	if err != nil {
		return nil, nil, err
	}

	// Run SPDZ point-add
	tripleIndex := 0
	x3Share, y3Share, err := SPDZPointAdd(conn, id, x1Share, y1Share, x2Share, y2Share, triples, &tripleIndex)
	if err != nil {
		return nil, nil, err
	}

	return modReduce(x3Share.V), modReduce(y3Share.V), nil
}

// ExpandLabelToField interprets the 16-byte Label as a 128-bit big.Int
// and reduces it modulo p256P to produce a valid field element.
func ExpandLabelToField(l ot.Label) *big.Int {
	var d ot.LabelData
	l.GetData(&d)
	x := new(big.Int).SetBytes(d[:])
	x.Mod(x, p256P)
	return x
}

func randomBools(n int) []bool {
	out := make([]bool, n)
	buf := make([]byte, (n+7)/8)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		out[i] = ((buf[i/8] >> (i % 8)) & 1) == 1
	}
	return out
}
