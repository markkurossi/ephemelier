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

// GenerateBeaverTriplesOT produces n Beaver triples (a,b,c) in additive shares using IKNP and CrossMultiplyViaOT.
// - conn: p2p connection between the two parties
// - oti: base OT instance (must be a fresh ot.OT implementation instance)
// - id: party id (0 or 1)
// - n: number of triples to produce
// - auditRate: optional fraction [0,1) to audit produced triples (set 0 to disable)
// Returns local shares of triples (length n) or error.
func GenerateBeaverTriplesOT(conn *p2p.Conn, oti ot.OT, id int, n int, auditRate float64) ([]*Triple, error) {
	if id != 0 && id != 1 {
		return nil, errors.New("id must be 0 or 1")
	}
	if n <= 0 {
		return nil, errors.New("n must be positive")
	}

	// Initialize base-OT roles before IKNP Setup
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

	// We'll operate in small batches to avoid large memory spikes; batch size tunable.
	const batchSize = 256

	for base := 0; base < n; base += batchSize {
		end := base + batchSize
		if end > n {
			end = n
		}
		m := end - base

		// -------------------------
		// Sample A shares via IKNP
		// -------------------------
		if id == 0 {
			// sender side: expand send to get wires (L0,L1)
			wires, err := ext.ExpandSend(m)
			if err != nil {
				return nil, fmt.Errorf("ExpandSend A: %w", err)
			}
			for i := 0; i < m; i++ {
				a0 := ExpandLabelToField(wires[i].L0)
				triples[base+i] = &Triple{A: NewShare(a0)}
			}
		} else {
			// receiver side: choose flags and receive labels
			flags := randomBools(m)
			labels, err := ext.ExpandReceive(flags)
			if err != nil {
				return nil, fmt.Errorf("ExpandReceive A: %w", err)
			}
			for i := 0; i < m; i++ {
				a1 := ExpandLabelToField(labels[i])
				triples[base+i] = &Triple{A: NewShare(a1)}
			}
		}

		// Exchange complementary A shares so both parties hold additive shares of a.
		if id == 0 {
			for i := 0; i < m; i++ {
				if err := sendField(conn, triples[base+i].A.V); err != nil {
					return nil, fmt.Errorf("send a0: %w", err)
				}
			}
			if err := conn.Flush(); err != nil {
				return nil, fmt.Errorf("flush a0: %w", err)
			}
		} else {
			for i := 0; i < m; i++ {
				a0, err := recvField(conn)
				if err != nil {
					return nil, fmt.Errorf("recv a0: %w", err)
				}
				aLabel := triples[base+i].A.V
				a1 := new(big.Int).Sub(aLabel, a0)
				a1.Mod(a1, p256P)
				triples[base+i].A = NewShare(a1)
			}
		}

		// -------------------------
		// Sample B shares via IKNP
		// -------------------------
		if id == 0 {
			wires, err := ext.ExpandSend(m)
			if err != nil {
				return nil, fmt.Errorf("ExpandSend B: %w", err)
			}
			for i := 0; i < m; i++ {
				b0 := ExpandLabelToField(wires[i].L0)
				triples[base+i].B = NewShare(b0)
			}
		} else {
			flags := randomBools(m)
			labels, err := ext.ExpandReceive(flags)
			if err != nil {
				return nil, fmt.Errorf("ExpandReceive B: %w", err)
			}
			for i := 0; i < m; i++ {
				b1 := ExpandLabelToField(labels[i])
				triples[base+i].B = NewShare(b1)
			}
		}

		// Exchange complementary B shares
		if id == 0 {
			for i := 0; i < m; i++ {
				if err := sendField(conn, triples[base+i].B.V); err != nil {
					return nil, fmt.Errorf("send b0: %w", err)
				}
			}
			if err := conn.Flush(); err != nil {
				return nil, fmt.Errorf("flush b0: %w", err)
			}
		} else {
			for i := 0; i < m; i++ {
				b0, err := recvField(conn)
				if err != nil {
					return nil, fmt.Errorf("recv b0: %w", err)
				}
				bLabel := triples[base+i].B.V
				b1 := new(big.Int).Sub(bLabel, b0)
				b1.Mod(b1, p256P)
				triples[base+i].B = NewShare(b1)
			}
		}

		// -------------------------
		// Compute C shares via CrossMultiplyViaOT
		// -------------------------
		for i := 0; i < m; i++ {
			aS := triples[base+i].A
			bS := triples[base+i].B

			cS, err := CrossMultiplyViaOT(conn, oti, id, aS, bS)
			if err != nil {
				return nil, fmt.Errorf("CrossMultiplyViaOT failed at idx %d: %w", base+i, err)
			}
			triples[base+i].C = cS
		}
	}

	// Optional auditing (enabled by auditRate > 0). If auditTriples not implemented it may return error.
	if auditRate > 0 {
		if err := auditTriples(conn, id, triples, auditRate); err != nil {
			return nil, fmt.Errorf("audit failed: %w", err)
		}
	}

	return triples, nil
}
