// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at https://golang.org/LICENSE.

package poly1305

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"testing"
)

// Poly1305 [RFC 7539] is a relatively simple MAC algorithm: the authentication
// tag for a 64 bytes message is approximately
//
//     s + m[0:16] * r⁴ + m[16:32] * r³ + m[32:48] * r² + m[48:64] * r  mod  2¹³⁰ - 5
//
// for some secret r and s. It can be computed sequentially like
//
//     for len(msg) > 0:
//         h += read(msg, 16)
//         h *= r
//         h %= 2¹³⁰ - 5
//     return h + s
//
// All the complexity is about doing performant constant-time math on numbers
// larger than any available numeric type.

// MAC is an io.Writer computing a Poly1305 authentication tag of the data
// written to it. After Sum has been called, Write must not be used anymore.
type MAC struct {
	macState

	buffer [TagSize]byte
	offset int
}

// TagSize is the size, in bytes, of a poly1305 authenticator.
const TagSize = 16

// New returns a new MAC for a single-use key.
func New(key *[32]byte) *MAC {
	h := &MAC{}
	initialize(key, &h.r, &h.s)
	return h
}

// Write splits the incoming message into TagSize chunks, and passes them to
// update. It buffers incomplete chunks.
func (h *MAC) Write(p []byte) (int, error) {
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if h.offset+n < TagSize {
			h.offset += n
			return len(p), nil
		}
		p = p[n:]
		h.offset = 0
		update(&h.macState, h.buffer[:])
	}
	if n := len(p) - (len(p) % TagSize); n > 0 {
		update(&h.macState, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return len(p), nil
}

// Sum flushes the last incomplete chunk from the buffer, if any, and generates
// the MAC output. It does not modify the MAC's state, in order to allow for
// multiple calls to Sum, even if no Write should be performed after Sum.
func (h *MAC) Sum(out *[TagSize]byte) {
	state := h.macState
	if h.offset > 0 {
		update(&state, h.buffer[:h.offset])
	}
	finalize(out, &state.h, &state.s)
}

// macState holds numbers in saturated 64-bit little-endian limbs. That is,
// the value of [x0, x1, x2] is x[0] + x[1] * 2⁶⁴ + x[2] * 2¹²⁸.
type macState struct {
	// h is the main accumulator. It is to be interpreted modulo 2¹³⁰ - 5, but
	// can grow larger during and after rounds.
	h [3]uint64
	// r and s are the private key components.
	r [2]uint64
	s [2]uint64
}

// [rMask0, rMask1] is the specified Poly1305 clamping mask in little-endian. It
// clears some bits of the secret coefficient to make it possible to implement
// multiplication more efficiently.
const (
	rMask0 = 0x0FFFFFFC0FFFFFFF
	rMask1 = 0x0FFFFFFC0FFFFFFC
)

func initialize(key *[32]byte, r, s *[2]uint64) {
	r[0] = binary.LittleEndian.Uint64(key[0:8]) & rMask0
	r[1] = binary.LittleEndian.Uint64(key[8:16]) & rMask1
	s[0] = binary.LittleEndian.Uint64(key[16:24])
	s[1] = binary.LittleEndian.Uint64(key[24:32])
}

// uint128 holds a 128-bit number as two 64-bit limbs, for use with the
// bits.Mul64 and bits.Add64 intrinsics.
type uint128 struct {
	lo, hi uint64
}

func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

func add128(a, b uint128) uint128 {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, c := bits.Add64(a.hi, b.hi, c)
	if c != 0 {
		panic("poly1305: unexpected overflow")
	}
	return uint128{lo, hi}
}

func shiftRightBy2(a uint128) uint128 {
	a.lo = a.lo>>2 | (a.hi&3)<<62
	a.hi = a.hi >> 2
	return a
}

// update absorbs msg into the state.h accumulator. For each chunk of 128
// bits of message, it computes
//
//	h₊ = (h + m) * r  mod  2¹³⁰ - 5
//
// If the msg length is not a multiple of TagSize, it assumes the last
// incomplete chunk is the final one.
func update(state *macState, msg []byte) {
	h0, h1, h2 := state.h[0], state.h[1], state.h[2]
	r0, r1 := state.r[0], state.r[1]

	var round int

	for len(msg) > 0 {
		var c uint64

		// For the first step, h + m, we use a chain of bits.Add64 intrinsics.
		// The resulting value of h might exceed 2¹³⁰ - 5, but will be partially
		// reduced at the end of the multiplication below.
		//
		// The spec requires us to set a bit just above the message size, not to
		// hide leading zeroes. For full chunks, that's 1 << 128, so we can just
		// add 1 to the most significant (2¹²⁸) limb, h2.
		if len(msg) >= TagSize {
			h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(msg[0:8]), 0)
			h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(msg[8:16]), c)
			h2 += c + 1

			msg = msg[TagSize:]
		} else {
			var buf [TagSize]byte
			copy(buf[:], msg)
			buf[len(msg)] = 1

			h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(buf[0:8]), 0)
			h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(buf[8:16]), c)
			h2 += c

			msg = nil
		}

		fmt.Printf("Round %d:\n", round)
		fmt.Printf(" - h0	 : %x\n", h0)
		fmt.Printf(" - h1	 : %x\n", h1)
		fmt.Printf(" - h2	 : %x\n", h2)

		// Multiplication of big number limbs is similar to elementary school
		// columnar multiplication. Instead of digits, there are 64-bit limbs.
		//
		// We are multiplying a 3 limbs number, h, by a 2 limbs number, r.
		//
		//                        h2    h1    h0  x
		//                              r1    r0  =
		//                       ----------------
		//                      h2r0  h1r0  h0r0     <-- individual 128-bit products
		//            +   h2r1  h1r1  h0r1
		//               ------------------------
		//                 m3    m2    m1    m0      <-- result in 128-bit overlapping limbs
		//               ------------------------
		//         m3.hi m2.hi m1.hi m0.hi           <-- carry propagation
		//     +         m3.lo m2.lo m1.lo m0.lo
		//        -------------------------------
		//           t4    t3    t2    t1    t0      <-- final result in 64-bit limbs
		//
		// The main difference from pen-and-paper multiplication is that we do
		// carry propagation in a separate step, as if we wrote two digit sums
		// at first (the 128-bit limbs), and then carried the tens all at once.

		h0r0 := mul64(h0, r0)
		h1r0 := mul64(h1, r0)
		h2r0 := mul64(h2, r0)
		h0r1 := mul64(h0, r1)
		h1r1 := mul64(h1, r1)
		h2r1 := mul64(h2, r1)

		// Since h2 is known to be at most 5 (see below), and r0 and r1 have their
		// top 4 bits cleared by the mask, we know that their product is not going
		// to overflow 64 bits, so we can ignore the high part of the products.
		//
		// This also means that the product doesn't have a fifth limb (t4).
		if h2r0.hi != 0 {
			panic("poly1305: unexpected overflow")
		}
		if h2r1.hi != 0 {
			panic("poly1305: unexpected overflow")
		}

		m0 := h0r0
		m1 := add128(h1r0, h0r1) // These two additions don't overflow thanks again
		m2 := add128(h2r0, h1r1) // to the 4 masked bits at the top of r0 and r1.
		m3 := h2r1

		t0 := m0.lo
		t1, c := bits.Add64(m1.lo, m0.hi, 0)
		t2, c := bits.Add64(m2.lo, m1.hi, c)
		t3, _ := bits.Add64(m3.lo, m2.hi, c)

		fmt.Printf("Round %d:\n", round)
		fmt.Printf(" - t0	 : %x\n", t0)
		fmt.Printf(" - t1	 : %x\n", t1)
		fmt.Printf(" - t2	 : %x\n", t2)
		fmt.Printf(" - t3	 : %x\n", t3)

		// Now we have the result as 4 64-bit limbs, and we need to reduce it
		// modulo 2¹³⁰ - 5. The special shape of this Crandall prime lets us do
		// a cheap partial reduction according to the reduction identity
		//
		//     c * 2¹³⁰ + n  =  c * 5 + n  mod  2¹³⁰ - 5
		//
		// because 2¹³⁰ = 5 mod 2¹³⁰ - 5. Partial reduction since the result is
		// likely to be larger than 2¹³⁰ - 5, but still small enough to fit the
		// assumptions we make about h in the rest of the code.
		//
		// See also https://speakerdeck.com/gtank/engineering-prime-numbers?slide=23

		// We split the final result at the 2¹³⁰ mark into h and cc, the carry.
		// Note that the carry bits are effectively shifted left by 2, in other
		// words, cc = c * 4 for the c in the reduction identity.
		h0, h1, h2 = t0, t1, t2&maskLow2Bits
		cc := uint128{t2 & maskNotLow2Bits, t3}

		// To add c * 5 to h, we first add cc = c * 4, and then add (cc >> 2) = c.

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c

		cc = shiftRightBy2(cc)

		fmt.Printf("Round %d:\n", round)
		fmt.Printf(" - cc    : %08x%08x\n", cc.hi, cc.lo)

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c

		fmt.Printf("Round %d:\n", round)
		fmt.Printf(" - h0	 : %x\n", h0)
		fmt.Printf(" - h1	 : %x\n", h1)
		fmt.Printf(" - h2	 : %x\n", h2)

		round++

		// h2 is at most 3 + 1 + 1 = 5, making the whole of h at most
		//
		//     5 * 2¹²⁸ + (2¹²⁸ - 1) = 6 * 2¹²⁸ - 1
	}

	state.h[0], state.h[1], state.h[2] = h0, h1, h2
}

const (
	maskLow2Bits    uint64 = 0x0000000000000003
	maskNotLow2Bits uint64 = ^maskLow2Bits
)

// select64 returns x if v == 1 and y if v == 0, in constant time.
func select64(v, x, y uint64) uint64 { return ^(v-1)&x | (v-1)&y }

// [p0, p1, p2] is 2¹³⁰ - 5 in little endian order.
const (
	p0 = 0xFFFFFFFFFFFFFFFB
	p1 = 0xFFFFFFFFFFFFFFFF
	p2 = 0x0000000000000003
)

// finalize completes the modular reduction of h and computes
//
//	out = h + s  mod  2¹²⁸
func finalize(out *[TagSize]byte, h *[3]uint64, s *[2]uint64) {
	h0, h1, h2 := h[0], h[1], h[2]

	fmt.Printf("Finalize:\n")
	fmt.Printf(" - h0	 : %x\n", h0)
	fmt.Printf(" - h1	 : %x\n", h1)
	fmt.Printf(" - h2	 : %x\n", h2)

	// After the partial reduction in update, h might be more than 2¹³⁰ - 5, but
	// will be less than 2 * (2¹³⁰ - 5). To complete the reduction in constant
	// time, we compute t = h - (2¹³⁰ - 5), and select h as the result if the
	// subtraction underflows, and t otherwise.

	t0, b := bits.Sub64(h0, p0, 0)
	t1, b := bits.Sub64(h1, p1, b)
	_, b = bits.Sub64(h2, p2, b)

	// h = h if h < p else h - p
	h0 = select64(b, h0, t0)
	h1 = select64(b, h1, t1)

	fmt.Printf("Selected:\n")
	fmt.Printf(" - h0	 : %x\n", h0)
	fmt.Printf(" - h1	 : %x\n", h1)
	fmt.Printf(" - h2	 : %x\n", h2)

	// Finally, we compute the last Poly1305 step
	//
	//     tag = h + s  mod  2¹²⁸
	//
	// by just doing a wide addition with the 128 low bits of h and discarding
	// the overflow.
	h0, c := bits.Add64(h0, s[0], 0)
	h1, _ = bits.Add64(h1, s[1], c)

	fmt.Printf("Final:\n")
	fmt.Printf(" - h0	 : %x\n", h0)
	fmt.Printf(" - h1	 : %x\n", h1)
	fmt.Printf(" - h2	 : %x\n", h2)

	binary.LittleEndian.PutUint64(out[0:8], h0)
	binary.LittleEndian.PutUint64(out[8:16], h1)
}

func TestPoly1305(t *testing.T) {
	var key = [32]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	var polyKey = [32]byte{
		0x12, 0x9d, 0x17, 0xa7, 0x9b, 0x52, 0xf1, 0xb2,
		0xbe, 0x1c, 0x6d, 0x8d, 0xfc, 0xc8, 0x3b, 0x50,
		0x19, 0x98, 0x26, 0x7a, 0x2e, 0xbf, 0x61, 0xa5,
		0xd8, 0x88, 0x66, 0xdb, 0x84, 0x80, 0x6a, 0xaf,
	}
	var cipher = []byte{
		0x05, 0xaf, 0xdc, 0x9b, 0x65, 0x5d, 0x2a, 0x04,
		0x8e, 0x1e, 0x97, 0xed, 0xae, 0x99, 0x3b, 0x7b,
		0x52, 0x9a, 0x6e, 0xee, 0x66, 0xeb, 0x9b, 0x81,
		0xe0, 0x1e,
	}
	aad := []byte("AAD example")
	fmt.Printf("AAD: %x\n", aad)

	input := make([]byte, len(aad)+5+len(cipher)+6+16)
	copy(input, aad)
	copy(input[16:], cipher)
	binary.LittleEndian.PutUint64(input[48:], uint64(len(aad)))
	binary.LittleEndian.PutUint64(input[56:], uint64(len(cipher)))

	fmt.Printf("len(input)=%v\n%s", len(input), hex.Dump(input))

	_ = key

	mac := New(&polyKey)
	mac.Write(input)

	var sum [TagSize]byte
	mac.Sum(&sum)

	fmt.Printf("tag: %x\n", sum[:])
}
