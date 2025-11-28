package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

// ---------- Constants & Helpers (P-256 prime) ----------

var (
	p256P *big.Int
)

func init() {
	p256P = elliptic.P256().Params().P
}

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

func read32ToBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

func sendField(conn *p2p.Conn, v *big.Int) error { return conn.SendData(bytes32(v)) }
func recvField(conn *p2p.Conn) (*big.Int, error) {
	b, err := conn.ReceiveData()
	if err != nil {
		return nil, err
	}
	return read32ToBig(b), nil
}

// ---------- SPDZ types ----------

type Share struct {
	V *big.Int
}

func NewShare(v *big.Int) *Share { return &Share{V: modReduce(v)} }
func AddShare(a, b *Share) *Share {
	z := new(big.Int).Add(a.V, b.V)
	return NewShare(z)
}
func SubShare(a, b *Share) *Share {
	z := new(big.Int).Sub(a.V, b.V)
	return NewShare(z)
}

// ---------- Beaver triple ----------

type Triple struct {
	A *Share
	B *Share
	C *Share
}

// Dealer triples (peer0 is dealer)
// Corrected: dealer samples global a,b, computes c=a*b, then splits into additive shares.
func GenerateBeaverTriplesDealer(conn *p2p.Conn, oti ot.OT, id int, n int) ([]*Triple, error) {
	triples := make([]*Triple, n)
	if id == 0 {
		for i := 0; i < n; i++ {
			// sample global values a,b
			aGlob, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}
			bGlob, err := randomFieldElement(rand.Reader)
			if err != nil {
				return nil, err
			}
			// c = a*b mod p
			cGlob := new(big.Int).Mod(new(big.Int).Mul(aGlob, bGlob), p256P)

			// sample random local shares for peer0
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

			// compute peer1 shares to make additive decomposition
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

			triples[i] = &Triple{
				A: NewShare(a0),
				B: NewShare(b0),
				C: NewShare(c0),
			}
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
			triples[i] = &Triple{
				A: NewShare(a1),
				B: NewShare(b1),
				C: NewShare(c1),
			}
		}
	}
	return triples, nil
}

// ---------- Open / reconstruction helpers ----------

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

// ---------- MulShare (Beaver) ----------

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
	// IMPORTANT: add d*e only on one party to avoid doubling.
	if id == 0 {
		tmp3 := new(big.Int).Mul(dv, ev)
		term.Add(term, tmp3)
	}
	term.Mod(term, p256P)

	return NewShare(term), nil
}

var m sync.Mutex

// ---------- safeMulDebug: debug version used in ExpShare ----------

func safeMulDebug(conn *p2p.Conn, id int, a, b *Share, triples []*Triple, tripleIndex *int, debugLimit int) (*Share, error) {
	if *tripleIndex >= len(triples) {
		return nil, errors.New("not enough triples for multiplication")
	}
	idx := *tripleIndex
	t := triples[idx]

	// If within debug window: open d,e and compute term locally and print
	if idx < debugLimit {
		// compute local d,e
		d := SubShare(a, t.A)
		e := SubShare(b, t.B)

		// open d,e (this consumes network round)
		dv, ev, err := openTwoShares(conn, id, d, e)
		if err != nil {
			return nil, err
		}

		// compute expected assembled term (match MulShare: only id==0 adds dv*ev)
		expected := new(big.Int).Set(t.C.V)
		tmp := new(big.Int).Mul(dv, t.B.V)
		expected.Add(expected, tmp)
		tmp2 := new(big.Int).Mul(ev, t.A.V)
		expected.Add(expected, tmp2)
		if id == 0 {
			tmp3 := new(big.Int).Mul(dv, ev)
			expected.Add(expected, tmp3)
		}
		expected.Mod(expected, p256P)

		// Print diagnostics
		m.Lock()
		fmt.Printf("DEBUG safeMulDebug idx=%d (peer %d):\n", idx, id)
		fmt.Printf("  triple.A (local) = %064x\n", t.A.V)
		fmt.Printf("  triple.B (local) = %064x\n", t.B.V)
		fmt.Printf("  triple.C (local) = %064x\n", t.C.V)
		fmt.Printf("  opened d = %064x\n", dv)
		fmt.Printf("  opened e = %064x\n", ev)
		fmt.Printf("  expected term = %064x\n", expected)
		m.Unlock()

		// consume triple
		*tripleIndex++

		// return share corresponding to expected term
		return NewShare(expected), nil
	}

	// fallback: normal MulShare and consume triple
	res, err := MulShare(conn, id, a, b, t)
	if err != nil {
		return nil, err
	}
	*tripleIndex++
	return res, nil
}

// ---------- ExpShare / InvShare (uses safeMulDebug) ----------

func ExpShare(conn *p2p.Conn, id int, x *Share, exponent *big.Int, triples []*Triple, tripleIndex *int) (*Share, error) {
	// initialize [res] = 1 (peer0 holds 1, peer1 holds 0)
	var res *Share
	if id == 0 {
		res = NewShare(big.NewInt(1))
	} else {
		res = NewShare(big.NewInt(0))
	}
	// copy of base
	base := NewShare(new(big.Int).Set(x.V))

	if exponent == nil {
		return nil, errors.New("nil exponent")
	}
	if exponent.Sign() == 0 {
		return res, nil
	}

	// debugLimit: how many first multiplications to print
	debugLimit := 64

	bitLen := exponent.BitLen()
	for i := bitLen - 1; i >= 0; i-- {
		// square
		var err error
		res, err = safeMulDebug(conn, id, res, res, triples, tripleIndex, debugLimit)
		if err != nil {
			return nil, err
		}
		// conditional multiply
		if exponent.Bit(i) == 1 {
			res, err = safeMulDebug(conn, id, res, base, triples, tripleIndex, debugLimit)
			if err != nil {
				return nil, err
			}
		}
	}
	// final resShare returned (not opened here)
	return res, nil
}

func InvShare(conn *p2p.Conn, id int, x *Share, triples []*Triple, tripleIndex *int) (*Share, error) {
	exp := new(big.Int).Sub(p256P, big.NewInt(2))
	return ExpShare(conn, id, x, exp, triples, tripleIndex)
}

// ---------- SPDZ point addition ----------

func SPDZPointAdd(conn *p2p.Conn, id int, x1, y1, x2, y2 *Share, triples []*Triple, tripleIndex *int) (*Share, *Share, error) {
	dx := SubShare(x2, x1)
	dy := SubShare(y2, y1)

	invDx, err := InvShare(conn, id, dx, triples, tripleIndex)
	if err != nil {
		return nil, nil, err
	}

	if *tripleIndex >= len(triples) {
		return nil, nil, errors.New("not enough triples for lam")
	}
	lam, err := MulShare(conn, id, dy, invDx, triples[*tripleIndex])
	if err != nil {
		return nil, nil, err
	}
	*tripleIndex++

	if *tripleIndex >= len(triples) {
		return nil, nil, errors.New("not enough triples for lam2")
	}
	lam2, err := MulShare(conn, id, lam, lam, triples[*tripleIndex])
	if err != nil {
		return nil, nil, err
	}
	*tripleIndex++

	tmp := SubShare(lam2, x1)
	x3 := SubShare(tmp, x2)

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

// ---------- Share input ----------

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

// ---------- Peer: top-level SPDZ online flow ----------

func Peer(oti ot.OT, id int, conn *p2p.Conn, xInput, yInput *big.Int) (xOut, yOut *big.Int, err error) {
	if id != 0 && id != 1 {
		return nil, nil, errors.New("id must be 0 or 1")
	}

	if id == 0 {
		if err := oti.InitSender(conn); err != nil {
			return nil, nil, err
		}
	} else {
		if err := oti.InitReceiver(conn); err != nil {
			return nil, nil, err
		}
	}

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

	triplesNeeded := 1600
	triples, err := GenerateBeaverTriplesDealer(conn, oti, id, triplesNeeded)
	if err != nil {
		return nil, nil, err
	}

	tripleIndex := 0
	x3Share, y3Share, err := SPDZPointAdd(conn, id, x1Share, y1Share, x2Share, y2Share, triples, &tripleIndex)
	if err != nil {
		return nil, nil, err
	}

	return modReduce(x3Share.V), modReduce(y3Share.V), nil
}
