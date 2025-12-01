package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/otext"
	"github.com/markkurossi/mpc/p2p"
	"github.com/markkurossi/mpc/vole"
)

// GenerateBeaverTriplesOTBatch generates n triples using batched IKNP and batched bitwise OT.
// Much faster than one-by-one CrossMultiplyViaOT.
func GenerateBeaverTriplesOTBatch(conn *p2p.Conn, oti ot.OT, id int, n int, auditRate float64) ([]*Triple, error) {
	if id != 0 && id != 1 {
		return nil, errors.New("id must be 0 or 1")
	}
	if n <= 0 {
		return nil, errors.New("n must be positive")
	}

	// init base-OT roles
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

	// We'll sample A and B in batches to limit memory use
	const batchSize = 1024 // tuneable; set to e.g. 1024 or 2048 depending on memory
	for base := 0; base < n; base += batchSize {
		end := base + batchSize
		if end > n {
			end = n
		}
		m := end - base

		// 1) Sample A shares via IKNP (batched)
		if id == 0 {
			// sender expands m wires
			wires, err := ext.ExpandSend(m)
			if err != nil {
				return nil, fmt.Errorf("ExpandSend A: %w", err)
			}
			for i := 0; i < m; i++ {
				a0 := ExpandLabelToField(wires[i].L0)
				triples[base+i] = &Triple{A: NewShare(a0)}
			}
		} else {
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

		// exchange complementary A shares
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

		// 2) Sample B shares via IKNP (batched)
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

		// exchange complementary B shares
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

		// 3) Batch cross-multiply: compute all cShares for triples[base:base+m]
		cShares, err := CrossMultiplyBatch(conn, oti, id, triples[base:base+m])
		if err != nil {
			return nil, fmt.Errorf("CrossMultiplyBatch failed: %w", err)
		}
		if len(cShares) != m {
			return nil, fmt.Errorf("CrossMultiplyBatch returned %d shares want %d", len(cShares), m)
		}
		for i := 0; i < m; i++ {
			triples[base+i].C = cShares[i]
		}
	}

	// optional audit
	if auditRate > 0 {
		if err := auditTriples(conn, id, triples, auditRate); err != nil {
			return nil, fmt.Errorf("audit failed: %w", err)
		}
	}

	return triples, nil
}

// CrossMultiplyBatch: batched version of CrossMultiplyViaOT for m triples.
// Input: list of triples with A and B shares filled (local shares).
// Output: slice of C shares (local contributions) length == len(triples).
func CrossMultiplyBatch(conn *p2p.Conn, oti ot.OT, id int, triples []*Triple) ([]*Share, error) {
	m := len(triples)
	if m == 0 {
		return nil, nil
	}

	// Helper that runs one VOLE direction and returns per-triple contributions (big.Int)
	runDirection := func(localIsSender bool) ([]*big.Int, error) {
		// construct vole extension with the appropriate role
		var role vole.Role
		if localIsSender {
			role = vole.SenderRole
		} else {
			role = vole.ReceiverRole
		}
		ve := vole.NewExt(oti, conn, role)
		if err := ve.Setup(rand.Reader); err != nil {
			return nil, fmt.Errorf("VOLE Setup(dir): %w", err)
		}

		// Build local input vector for this direction:
		// - If local is sender, senderInputs = local A shares (triples[t].A.V)
		// - If local is receiver, receiverInputs = local B shares (triples[t].B.V)
		if localIsSender {
			xs := make([]*big.Int, m)
			for t := 0; t < m; t++ {
				xs[t] = triples[t].A.V
			}
			// MulSender returns r_i (sender masks)
			rs, err := ve.MulSender(xs, p256P)
			if err != nil {
				return nil, fmt.Errorf("VOLE MulSender: %w", err)
			}
			if len(rs) != m {
				return nil, fmt.Errorf("VOLE MulSender returned %d masks, want %d", len(rs), m)
			}
			// Sender's contribution for this direction is -r_i mod p
			out := make([]*big.Int, m)
			for t := 0; t < m; t++ {
				neg := new(big.Int).Neg(rs[t])
				neg.Mod(neg, p256P)
				out[t] = neg
			}
			return out, nil
		} else {
			ys := make([]*big.Int, m)
			for t := 0; t < m; t++ {
				ys[t] = triples[t].B.V
			}
			// MulReceiver returns u_i = r_i + x_i*y_i
			us, err := ve.MulReceiver(ys, p256P)
			if err != nil {
				return nil, fmt.Errorf("VOLE MulReceiver: %w", err)
			}
			if len(us) != m {
				return nil, fmt.Errorf("VOLE MulReceiver returned %d values, want %d", len(us), m)
			}
			// Receiver's contribution for this direction is u_i
			return us, nil
		}
	}

	// Direction 1: local is sender for dir1 iff id == 0
	localIsSenderForDir1 := (id == 0)
	term1, err := runDirection(localIsSenderForDir1)
	if err != nil {
		return nil, err
	}

	// Direction 2: roles swapped (local is sender for dir2 iff id == 1)
	localIsSenderForDir2 := (id == 1)
	term2, err := runDirection(localIsSenderForDir2)
	if err != nil {
		return nil, err
	}

	// Combine per-triple contributions:
	// final sum = localProd + term1 + term2  (each term already mod p and signed correctly)
	cShares := make([]*Share, m)
	for t := 0; t < m; t++ {
		sum := new(big.Int).SetInt64(0)
		// local product a_t * b_t
		localProd := new(big.Int).Mul(triples[t].A.V, triples[t].B.V)
		localProd.Mod(localProd, p256P)
		sum.Add(sum, localProd)

		sum.Add(sum, term1[t])
		sum.Add(sum, term2[t])
		sum.Mod(sum, p256P)
		cShares[t] = NewShare(sum)
	}

	return cShares, nil
}
