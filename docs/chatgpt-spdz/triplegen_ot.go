package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/otext"
	"github.com/markkurossi/mpc/p2p"
)

// -----------------------------------------------------------------------------
// GenerateBeaverTriplesOT
// -----------------------------------------------------------------------------

func GenerateBeaverTriplesOT(conn *p2p.Conn, oti ot.OT, id int, n int, auditRate float64) ([]*Triple, error) {
	if id != 0 && id != 1 {
		return nil, errors.New("id must be 0 or 1")
	}
	if n <= 0 {
		return nil, errors.New("n must be positive")
	}

	// Base OT role must be initialized before IKNP Setup.
	if id == 0 {
		if err := oti.InitSender(conn); err != nil {
			return nil, fmt.Errorf("InitSender: %w", err)
		}
	} else {
		if err := oti.InitReceiver(conn); err != nil {
			return nil, fmt.Errorf("InitReceiver: %w", err)
		}
	}

	role := otext.SenderRole
	if id == 1 {
		role = otext.ReceiverRole
	}

	ext := otext.NewIKNPExt(oti, conn, role)

	if err := ext.Setup(rand.Reader); err != nil {
		return nil, fmt.Errorf("IKNP Setup: %w", err)
	}

	triples := make([]*Triple, n)

	const batchSize = 1024
	for base := 0; base < n; base += batchSize {
		end := base + batchSize
		if end > n {
			end = n
		}
		m := end - base

		// ---------------------------
		// 1. A values via IKNP
		// ---------------------------
		if id == 0 {
			wires, err := ext.ExpandSend(m)
			if err != nil {
				return nil, fmt.Errorf("ExpandSend(A): %w", err)
			}
			for i := 0; i < m; i++ {
				a0 := ExpandLabelToField(wires[i].L0)
				triples[base+i] = &Triple{A: NewShare(a0)}
			}
		} else {
			flags := randomBools(m)
			labels, err := ext.ExpandReceive(flags)
			if err != nil {
				return nil, fmt.Errorf("ExpandReceive(A): %w", err)
			}
			for i := 0; i < m; i++ {
				a1 := ExpandLabelToField(labels[i])
				triples[base+i] = &Triple{A: NewShare(a1)}
			}
		}

		// Exchange complementary A shares.
		if id == 0 {
			for i := 0; i < m; i++ {
				if err := sendField(conn, triples[base+i].A.V); err != nil {
					return nil, err
				}
			}
			conn.Flush()
		} else {
			for i := 0; i < m; i++ {
				a0, err := recvField(conn)
				if err != nil {
					return nil, err
				}
				aLabel := triples[base+i].A.V
				a1 := new(big.Int).Sub(aLabel, a0)
				a1.Mod(a1, p256P)
				triples[base+i].A = NewShare(a1)
			}
		}

		// ---------------------------
		// 2. B values via IKNP
		// ---------------------------
		if id == 0 {
			wires, err := ext.ExpandSend(m)
			if err != nil {
				return nil, fmt.Errorf("ExpandSend(B): %w", err)
			}
			for i := 0; i < m; i++ {
				b0 := ExpandLabelToField(wires[i].L0)
				triples[base+i].B = NewShare(b0)
			}
		} else {
			flags := randomBools(m)
			labels, err := ext.ExpandReceive(flags)
			if err != nil {
				return nil, fmt.Errorf("ExpandReceive(B): %w", err)
			}
			for i := 0; i < m; i++ {
				b1 := ExpandLabelToField(labels[i])
				triples[base+i].B = NewShare(b1)
			}
		}

		if id == 0 {
			for i := 0; i < m; i++ {
				if err := sendField(conn, triples[base+i].B.V); err != nil {
					return nil, err
				}
			}
			conn.Flush()
		} else {
			for i := 0; i < m; i++ {
				b0, err := recvField(conn)
				if err != nil {
					return nil, err
				}
				bLabel := triples[base+i].B.V
				b1 := new(big.Int).Sub(bLabel, b0)
				b1.Mod(b1, p256P)
				triples[base+i].B = NewShare(b1)
			}
		}

		// ---------------------------
		// 3. C = A * B
		// ---------------------------
		for i := 0; i < m; i++ {
			aS := triples[base+i].A
			bS := triples[base+i].B

			// Try OT-based cross multiplication.
			cS, err := CrossMultiplyViaOT(conn, oti, id, aS, bS)
			if err == nil {
				triples[base+i].C = cS
				continue
			}

			// Dealer fallback.
			if id == 0 {
				// Receive other shares
				a1, err := recvField(conn)
				if err != nil {
					return nil, err
				}
				b1, err := recvField(conn)
				if err != nil {
					return nil, err
				}

				a0 := aS.V
				b0 := bS.V

				aTot := new(big.Int).Add(a0, a1)
				bTot := new(big.Int).Add(b0, b1)
				aTot.Mod(aTot, p256P)
				bTot.Mod(bTot, p256P)

				cTot := new(big.Int).Mul(aTot, bTot)
				cTot.Mod(cTot, p256P)

				c1, _ := randomFieldElement(rand.Reader)
				c0 := new(big.Int).Sub(cTot, c1)
				c0.Mod(c0, p256P)

				triples[base+i].C = NewShare(c0)

				if err := sendField(conn, c1); err != nil {
					return nil, err
				}
			} else {
				if err := sendField(conn, aS.V); err != nil {
					return nil, err
				}
				if err := sendField(conn, bS.V); err != nil {
					return nil, err
				}
				c1, err := recvField(conn)
				if err != nil {
					return nil, err
				}
				triples[base+i].C = NewShare(c1)
			}
		}
	}

	if auditRate > 0 {
		if err := auditTriples(conn, id, triples, auditRate); err != nil {
			return nil, err
		}
	}

	return triples, nil
}
