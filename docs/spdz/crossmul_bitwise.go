package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/otext"
	"github.com/markkurossi/mpc/p2p"
)

// -----------------------------------------------------------------------------
// Bitwise OT multiplication
//
// Performs two IKNP-based OTs per bit (high 16 bytes + low 16 bytes) = 512 OTs.
// Runs two directions (sender/receiver swapped) = 1024 OTs per multiplication.
// Correct in the semi-honest model and compatible with your IKNP code.
// -----------------------------------------------------------------------------

const (
	fieldBits       = 256
	bytesPerChunk   = 16 // 16 bytes = 128 bits per OT label
	chunksPerField  = 2  // we split 32-byte field element into 2×16-byte chunks
	otsPerBit       = 2  // high chunk + low chunk
	otsPerDirection = fieldBits * otsPerBit
)

// CrossMultiplyViaOT computes a share of a*b using bitwise OT multiplication.
// Works with your existing single-label IKNP extension.
func CrossMultiplyViaOT(conn *p2p.Conn, oti ot.OT, id int, aShare *Share, bShare *Share) (*Share, error) {
	a := new(big.Int).Set(aShare.V)
	b := new(big.Int).Set(bShare.V)

	// Direction 1: peer 0 acts as OT sender, peer 1 as OT receiver
	dir1IsSender := (id == 0)

	// Direction 2: roles swapped
	dir2IsSender := (id == 1)

	share1, err := runBitwiseDirection(conn, oti, id, dir1IsSender, a, b)
	if err != nil {
		return nil, fmt.Errorf("dir1 failed: %w", err)
	}
	share2, err := runBitwiseDirection(conn, oti, id, dir2IsSender, a, b)
	if err != nil {
		return nil, fmt.Errorf("dir2 failed: %w", err)
	}

	// local product
	localProd := new(big.Int).Mul(a, b)
	localProd.Mod(localProd, p256P)

	out := new(big.Int).Add(localProd, share1)
	out.Add(out, share2)
	out.Mod(out, p256P)

	return NewShare(out), nil
}

// -----------------------------------------------------------------------------
// One OT direction
// -----------------------------------------------------------------------------

func runBitwiseDirection(conn *p2p.Conn, oti ot.OT, id int, localIsSender bool, a, b *big.Int) (*big.Int, error) {

	// Initialize base OT roles
	if localIsSender {
		if err := oti.InitSender(conn); err != nil {
			return nil, err
		}
	} else {
		if err := oti.InitReceiver(conn); err != nil {
			return nil, err
		}
	}

	role := otext.ReceiverRole
	if localIsSender {
		role = otext.SenderRole
	}

	ext := otext.NewIKNPExt(oti, conn, role)
	if err := ext.Setup(rand.Reader); err != nil {
		return nil, err
	}

	if localIsSender {
		return runBitwiseSender(conn, ext, a)
	} else {
		return runBitwiseReceiver(conn, ext, a, b)
	}
}

// -----------------------------------------------------------------------------
// Sender side: sends masked pairs (u0, u1) for each bit
// -----------------------------------------------------------------------------

func runBitwiseSender(conn *p2p.Conn, ext *otext.IKNPExt, a *big.Int) (*big.Int, error) {

	// Precompute 2^j mod p
	powers := make([]*big.Int, fieldBits)
	powers[0] = big.NewInt(1)
	for j := 1; j < fieldBits; j++ {
		powers[j] = new(big.Int).Lsh(powers[j-1], 1)
		powers[j].Mod(powers[j], p256P)
	}

	type pair struct {
		r  *big.Int
		u0 []byte
		u1 []byte
	}

	pairs := make([]pair, fieldBits)
	sumR := big.NewInt(0)

	for j := 0; j < fieldBits; j++ {
		rj, err := randomFieldElement(rand.Reader)
		if err != nil {
			return nil, err
		}
		aj := new(big.Int).Mul(a, powers[j])
		aj.Mod(aj, p256P)

		u1 := new(big.Int).Add(rj, aj)
		u1.Mod(u1, p256P)

		pairs[j] = pair{
			r:  rj,
			u0: bigIntTo32Bytes(rj),
			u1: bigIntTo32Bytes(u1),
		}

		sumR.Add(sumR, rj)
		sumR.Mod(sumR, p256P)
	}

	totalChunks := otsPerDirection // = 512
	wires, err := ext.ExpandSend(totalChunks)
	if err != nil {
		return nil, err
	}
	if len(wires) != totalChunks {
		return nil, fmt.Errorf("ExpandSend returned %d wires", len(wires))
	}

	// Build delta buffer: for each chunk we send D0||D1
	out := make([]byte, 0, totalChunks*bytesPerChunk*2)

	for j := 0; j < fieldBits; j++ {

		// high chunk = first 16 bytes
		high0 := pairs[j].u0[0:16]
		high1 := pairs[j].u1[0:16]
		// low chunk = last 16 bytes
		low0 := pairs[j].u0[16:32]
		low1 := pairs[j].u1[16:32]

		chunks := []struct {
			m0 []byte
			m1 []byte
		}{
			{high0, high1},
			{low0, low1},
		}

		for c := 0; c < 2; c++ {
			w := wires[j*2+c]
			var d0, d1 ot.LabelData
			w.L0.GetData(&d0)
			w.L1.GetData(&d1)

			pad0 := labelPRG(d0[:], bytesPerChunk)
			pad1 := labelPRG(d1[:], bytesPerChunk)

			D0 := xorBytes(chunks[c].m0, pad0)
			D1 := xorBytes(chunks[c].m1, pad1)

			out = append(out, D0...)
			out = append(out, D1...)
		}
	}

	// Send all deltas
	if err := conn.SendData(out); err != nil {
		return nil, err
	}
	if err := conn.Flush(); err != nil {
		return nil, err
	}

	// Contribution = -sumR mod p
	neg := new(big.Int).Neg(sumR)
	neg.Mod(neg, p256P)
	return neg, nil
}

// -----------------------------------------------------------------------------
// Receiver side: obtains chosen messages u_{b_j}
// -----------------------------------------------------------------------------

func runBitwiseReceiver(conn *p2p.Conn, ext *otext.IKNPExt, a, b *big.Int) (*big.Int, error) {

	flags := make([]bool, otsPerDirection)
	for j := 0; j < fieldBits; j++ {
		bit := b.Bit(j) == 1
		flags[j*2+0] = bit
		flags[j*2+1] = bit
	}

	labels, err := ext.ExpandReceive(flags)
	if err != nil {
		return nil, err
	}
	if len(labels) != otsPerDirection {
		return nil, fmt.Errorf("ExpandReceive returned %d labels", len(labels))
	}

	totalDeltaBytes := otsPerDirection * 2 * bytesPerChunk
	deltaBuf, err := conn.ReceiveData()
	if err != nil {
		return nil, err
	}
	if len(deltaBuf) != totalDeltaBytes {
		return nil, fmt.Errorf("short delta buffer")
	}

	sum := big.NewInt(0)

	for j := 0; j < fieldBits; j++ {

		var uBytes [32]byte // reconstructed 32-byte block

		for c := 0; c < 2; c++ {

			off := (j*2 + c) * 2 * bytesPerChunk
			D0 := deltaBuf[off : off+bytesPerChunk]
			D1 := deltaBuf[off+bytesPerChunk : off+2*bytesPerChunk]

			var ld ot.LabelData
			labels[j*2+c].GetData(&ld)

			pad := labelPRG(ld[:], bytesPerChunk)

			var chosen []byte
			if flags[j*2+c] {
				chosen = xorBytes(D1, pad)
			} else {
				chosen = xorBytes(D0, pad)
			}

			if c == 0 {
				copy(uBytes[0:16], chosen)
			} else {
				copy(uBytes[16:32], chosen)
			}
		}

		uVal := new(big.Int).SetBytes(uBytes[:])
		uVal.Mod(uVal, p256P)

		sum.Add(sum, uVal)
		sum.Mod(sum, p256P)
	}

	return sum, nil
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

func bigIntTo32Bytes(x *big.Int) []byte {
	b := x.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func labelPRG(key []byte, n int) []byte {
	out := make([]byte, n)
	block, _ := aes.NewCipher(key)
	var ctr [16]byte
	var tmp [16]byte

	blocks := (n + 15) / 16
	for i := 0; i < blocks; i++ {
		binary.BigEndian.PutUint64(ctr[8:], uint64(i))
		block.Encrypt(tmp[:], ctr[:])
		start := i * 16
		end := start + 16
		if end > n {
			end = n
		}
		copy(out[start:end], tmp[:end-start])
	}
	return out
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
