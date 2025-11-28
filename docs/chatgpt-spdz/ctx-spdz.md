# Overview

This document specifies a semi-honest secure two-party protocol for
computing the elliptic curve addition R = P + Q over the NIST P-256
curve using a SPDZ-style arithmetic MPC with Beaver triples generated
via oblivious transfer (OT).

## Security Model

The protocol operates in the semi-honest model, meaning both peers
follow the protocol as specified but may try to extract information
from received messages. The protocol ensures that no additional
information is leaked.

No active-security (malicious) protections are included.  There are no
MACs, no global α, no triple checking, no sacrifice steps, and no
malicious OT extensions.

## Inputs

In the beginning:
 - Peer 0 holds the full plaintext point P.
 - Peer 1 holds the full plaintext point Q.
These points are not shared initially. The protocol begins by
secret-sharing these two input points inside SPDZ so that neither peer
learns the other peer’s input. The goal is to securely compute the
elliptic curve addition P+Q.

## Results

The protocol implements P-256 field arithmetic explicitly (including
reductions modulo the P-256 field prime) inside SPDZ so that the
resulting coordinates match the true P-256 point addition result. The
point-at-infinity MUST be represented consistently using the encoding
defined inside `spdz.go`.

After the addition, the resulting coordinates are reduced modulo the
P-256 field prime and output from SPDZ as integers in the range [0,
p256-1]. Each coordinate is then secret-shared between the two peers
as uint256 integers, such that the arithmetic sum of the two shares
(modulo 2^256) reconstructs the final coordinate outside the MPC.

This design ensures that the MPC output is a simple pair of uint256
values instead of P-256 curve points, while still enabling full
reconstruction of the resulting (x, y) point.

Each party learns only its own input values and its own output shares;
neither party learns the other party’s input or the cleartext result
of the P-256 point addition.

# Implementation

The protocol is implemented in Go as the function `Peer` in `spdz.go`:

```go
import (
    "github.com/markkurossi/mpc/p2p"
    "github.com/markkurossi/mpc/ot"
)

func Peer(oti ot.OT, id int, c *p2p.Conn, xInput, yInput *big.Int) (xOut, yOut *big.Int, err error)
```

The `Peer` function's arguments are:
 - `oti`: an oblivious transfer instance. This must implement the
   `ot.OT` interface defined below.
- `id`: peer identifier (0 or 1). The id determines the peer's role in
   message ordering. Peer 0 acts as the initiator (sends first)
   whenever the protocol requires ordered communication between peers.
 - `c`: a bidirectional connection between the two peers
 - `xInput` and `yInput`: the peer’s plaintext coordinates of its own
   input point (P for peer 0, Q for peer 1). These values are
   secret-shared inside SPDZ during the input phase of the protocol.
   The other peer does not receive these plaintext values.

The function returns:
 - `xOut` and `yOut`: the peer’s additive shares (as uint256 integers)
   of the resulting coordinate after computing P+Q.
 - `err`: non-nil if the protocol fails.

The Peer function uses oblivious transfer from the `ot` package to
generate Beaver triples for semi-honest SPDZ multiplications. No
malicious-security consistency checks or MAC verifications are
performed.

In the semi-honest model, OT is used only for standard Beaver triple
generation. No malicious OT extension checks (e.g., correlation
checks, consistency tests) are required.

All SPDZ messages exchanged in the Peer function use the
`p2p.Conn` API defined in this document below (The Connection API).

Higher-level SPDZ message formats (framing, tags, field encodings) are
implemented inside spdz.go using the low-level primitives provided by
the `p2p.Conn` API. The protocol defines its own framing and tagging
for SPDZ operations inside `spdz.go`.

All big.Int values are serialized as 32-byte big-endian values and
transmitted with the `SendData` and `ReceiveData` functions.

Both peers execute the same Peer function. The id parameter
distinguishes the two roles during message ordering.

## Test Runner

The framework has a test runner that sets up the peers, creates their
inputs and runs both peers as goroutines:

```go
package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

func main() {

	gr, ew := io.Pipe()
	er, gw := io.Pipe()

	gio := newReadWriter(gr, gw)
	eio := newReadWriter(er, ew)

	var wg sync.WaitGroup
	var oti = ot.NewCO(rand.Reader)

	var ex, ey *big.Int

	wg.Go(func() {
		x, okx := new(big.Int).SetString("7aaf9286743dc0adbd8fa93d305521cf0f62947ee5831bc8e355b133de65bd5a", 16)
		y, oky := new(big.Int).SetString("5e183e2d1f66256cc42883de880fdc7c177e99f2e003a2dd298e458aaebcc799", 16)
		if !(okx && oky) {
			panic("e")
		}
		var err error
		ex, ey, err = Peer(oti, 1, p2p.NewConn(eio), x, y)
		if err != nil {
			panic(err)
		}
	})

	x, okx := new(big.Int).SetString("bb32c4722cbd5a05510cfbb9c4c152f144e70fa24b9e428b9b3bf9f39dd43bbe", 16)
	y, oky := new(big.Int).SetString("25b7f3d9d79e5ca057b0ba7a940d5c917d41cc0a08d41cb1b2b83905e795c7db", 16)
	if !(okx && oky) {
		panic("g")
	}

	gx, gy, err := Peer(oti, 0, p2p.NewConn(gio), x, y)
	if err != nil {
		panic(err)
	}

	wg.Wait()

	fmt.Printf("gx: %v\n", gx.Text(16))
	fmt.Printf("gy: %v\n", gy.Text(16))
	fmt.Printf("ex: %v\n", ex.Text(16))
	fmt.Printf("ey: %v\n", ey.Text(16))
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
```

## The Connection API

The `p2p.Conn` has the following functions:

```go
func (conn *Conn) SendByte(val byte) error
func (conn *Conn) SendUint16(val int) error
func (conn *Conn) SendUint32(val int) error
func (conn *Conn) SendData(val []byte) error
func (conn *Conn) SendLabel(val ot.Label, data *ot.LabelData) error
func (conn *Conn) ReceiveByte() (byte, error)
func (conn *Conn) ReceiveUint16() (int, error)
func (conn *Conn) ReceiveUint32() (int, error)
func (conn *Conn) ReceiveData() ([]byte, error)
func (conn *Conn) ReceiveLabel(val *ot.Label, data *ot.LabelData) error
func (conn *Conn) Flush() error
```

The connection buffers writes to optimize network throughput. Once
peer is done sending data, it must `Flush` the connection to ensure
all data is written:

```go
// Send (x, y)
buf = x.FillBytes(make([]byte, 32))
err = conn.SendData(buf)
if err != nil {
    return err
}
buf = y.FillBytes(make([]byte, 32))
err = conn.SendData(buf)
if err != nil {
    return err
}
// Make sure all data is written.
err = conn.Flush()
if err != nil {
    return err
}
```

## The Oblivious Transfer (OT) API

```go
// Package ot implements oblivious transfer protocols.
package ot

// OT defines the base 1-out-of-2 Oblivious Transfer protocol. The
// sender uses the Send function to send a []Wire array where each
// wire has zero and one Label. The receiver calls Receive with a
// []bool array of selection bits. The higher level protocol must
// ensure the []Wire and []bool array lengths match.
type OT interface {
	// InitSender initializes the OT sender.
	InitSender(io IO) error

	// InitReceiver initializes the OT receiver.
	InitReceiver(io IO) error

	// Send sends the wire labels with OT.
	Send(wires []Wire) error

	// Receive receives the wire labels with OT based on the flag values.
	Receive(flags []bool, result []Label) error
}
```

The `Label` and `Wire` are defined as follows with their respective
operations:

```go

// Wire implements a wire with 0 and 1 labels.
type Wire struct {
	L0 []Label
	L1 []Label
}

// Label implements a 128 bit wire label.
type Label struct {
	D0 uint64
	D1 uint64
}

// LabelData contains lable data as byte array.
type LabelData [16]byte

func (l Label) String() string {
	return fmt.Sprintf("%016x%016x", l.D0, l.D1)
}

// Equal test if the labels are equal.
func (l Label) Equal(o Label) bool {
	return l.D0 == o.D0 && l.D1 == o.D1
}

// NewLabel creates a new random label.
func NewLabel(rand io.Reader) (Label, error) {
	var buf LabelData
	var label Label

	if _, err := rand.Read(buf[:]); err != nil {
		return label, err
	}
	label.SetData(&buf)
	return label, nil
}

// NewTweak creates a new label from the tweak value.
func NewTweak(tweak uint32) Label {
	return Label{
		D1: uint64(tweak),
	}
}

// S tests the label's S bit.
func (l Label) S() bool {
	return (l.D0 & 0x8000000000000000) != 0
}

// SetS sets the label's S bit.
func (l *Label) SetS(set bool) {
	if set {
		l.D0 |= 0x8000000000000000
	} else {
		l.D0 &= 0x7fffffffffffffff
	}
}

// Mul2 multiplies the label by 2.
func (l *Label) Mul2() {
	l.D0 <<= 1
	l.D0 |= (l.D1 >> 63)
	l.D1 <<= 1
}

// Mul4 multiplies the label by 4.
func (l *Label) Mul4() {
	l.D0 <<= 2
	l.D0 |= (l.D1 >> 62)
	l.D1 <<= 2
}

// Xor xors the label with the argument label.
func (l *Label) Xor(o Label) {
	l.D0 ^= o.D0
	l.D1 ^= o.D1
}

// GetData gets the labels as label data.
func (l Label) GetData(buf *LabelData) {
	binary.BigEndian.PutUint64(buf[0:8], l.D0)
	binary.BigEndian.PutUint64(buf[8:16], l.D1)
}

// SetData sets the labels from label data.
func (l *Label) SetData(data *LabelData) {
	l.D0 = binary.BigEndian.Uint64((*data)[0:8])
	l.D1 = binary.BigEndian.Uint64((*data)[8:16])
}

// Bytes returns the label data as bytes.
func (l Label) Bytes(buf *LabelData) []byte {
	l.GetData(buf)
	return buf[:]
}

// SetBytes sets the label data from bytes.
func (l *Label) SetBytes(data []byte) {
	l.D0 = binary.BigEndian.Uint64(data[0:8])
	l.D1 = binary.BigEndian.Uint64(data[8:16])
}
```

The ot package is used to implement the base 1-out-of-2 OT. Any OT
extensions are implemented on top of the base OT in `spdz.go`.

Peer 0 initializes the OT sender role, and Peer 1 initializes the OT
receiver role. This corresponds to the standard SPDZ setup where one
party plays the OT sender for triple generation and the other plays
the receiver.

## SPDZ Field Arithmetic

This section defines the finite field arithmetic used by the
semi-honest SPDZ engine inside `spdz.go`.  The arithmetic follows the
same semantics as the MP-SPDZ `gfp` field.  For correctness and
interoperability, the implementation uses Go’s `math/big` library
internally and provides explicit conversion helpers to and from the
fixed 4×64-bit limb representation used by the rest of the protocol.

All SPDZ computations in this protocol operate over the base field of
the NIST P-256 curve.

### P-256 Field Prime

All field elements are integers modulo the P-256 prime

```go
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
  = 2^256 - 2^224 + 2^192 + 2^96 - 1
```

This prime must be loaded at initialization time:

```go
var fieldModP = new(big.Int).SetBytes([]byte{
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
})
```

All arithmetic must produce results reduced modulo this prime.

### FieldElement Definition

A field element is represented as a wrapper around a `*big.Int` whose
value is always reduced to the canonical range `[0, p - 1]`.

```go
// FieldElement represents an element of GF(p256).
type FieldElement struct {
    v *big.Int  // always 0 <= v < p
}
```

Constructors:

```go
func FieldElementFromBig(x *big.Int) *FieldElement {
    z := new(big.Int).Mod(x, fieldModP)
    return &FieldElement{v: z}
}

func FieldElementFromUint64(x uint64) *FieldElement {
    return &FieldElement{v: new(big.Int).SetUint64(x)}
}
```

All SPDZ computations must use canonical values only. Any conversion
into a FieldElement must reduce modulo `p`.

### Limb Encoding (4 x 64-bit)

Although arithmetic uses big.Int, the protocol requires deterministic
256-bit encodings for SPDZ wires, OT messages, and label expansion.
Conversions follow little-endian ordering for limbs.

**Convert to limbs**

```go
// Returns 4 x 64-bit limbs in little-endian order
func (f *FieldElement) ToLimbs() [4]uint64 {
    var out [4]uint64
    b := f.v.Bytes()                 // big-endian integer bytes
    padded := make([]byte, 32)
    copy(padded[32-len(b):], b)

    for i := 0; i < 4; i++ {
        out[i] = binary.LittleEndian.Uint64(padded[i*8 : (i+1)*8])
    }
    return out
}
```

**Convert from limbs**

```go
func FieldElementFromLimbs(limbs [4]uint64) *FieldElement {
    buf := make([]byte, 32)
    for i := 0; i < 4; i++ {
        binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], limbs[i])
    }
    z := new(big.Int).SetBytes(buf) // big-endian
    z.Mod(z, fieldModP)
    return &FieldElement{v: z}
}
```

These conversions guarantee a consistent and stable on-wire representation.

### Serialization

Each SPDZ field element is serialized as a 32 byte big-endian value:

```go
func (f *FieldElement) Bytes32() []byte {
    out := make([]byte, 32)
    b := f.v.Bytes()
    copy(out[32-len(b):], b)
    return out
}

func FieldElementFromBytes32(buf []byte) *FieldElement {
    z := new(big.Int).SetBytes(buf)
    z.Mod(z, fieldModP)
    return &FieldElement{v: z}
}
```

All SPDZ operands must use this format when sent through `p2p.Conn`.

### Field Operations

All arithmetic must match MP-SPDZ behavior: operations are performed
on big integers and then reduced modulo `p`. The definitions below
serve as the reference implementation.

**Addition**

```go
func (a *FieldElement) Add(b *FieldElement) *FieldElement {
    z := new(big.Int).Add(a.v, b.v)
    z.Mod(z, fieldModP)
    return &FieldElement{v: z}
}
```

**Subtraction**

```go
func (a *FieldElement) Sub(b *FieldElement) *FieldElement {
    z := new(big.Int).Sub(a.v, b.v)
    if z.Sign() < 0 {
        z.Add(z, fieldModP)
    }
    return &FieldElement{v: z}
}
```

**Multiplication**

```go
func (a *FieldElement) Mul(b *FieldElement) *FieldElement {
    z := new(big.Int).Mul(a.v, b.v)
    z.Mod(z, fieldModP)
    return &FieldElement{v: z}
}
```

**Negation**

```go
func (a *FieldElement) Neg() *FieldElement {
    if a.v.Sign() == 0 {
        return FieldElementFromUint64(0)
    }
    z := new(big.Int).Sub(fieldModP, a.v)
    return &FieldElement{v: z}
}
```

**Inversion**

Inversion is required only if affine coordinate formulas are used inside SPDZ.

```go
func (a *FieldElement) Inv() *FieldElement {
    z := new(big.Int).ModInverse(a.v, fieldModP)
    return &FieldElement{v: z}
}
```

The inversion function returns `a^(p-2) mod p` using the standard
extended Euclidean algorithm implemented inside `ModInverse`.

### Notes for Implementers

1. This math/big implementation is the correctness reference.

2. When the SPDZ triple generation and EC arithmetic are verified to
   be correct, the multiplication and reduction routines may be
   optimized with limb-level or Solinas reduction, but all
   optimizations must produce identical canonical outputs.

3. All SPDZ operations that accept or output field elements must use
   the canonical `[0, p-1]` range and the 32 byte big-endian encoding.

4. All conversions to and from limbs must use the exact definitions
   above to ensure identical behavior between both peers.

## Label Expansion and PRF Mapping

This section defines how 128-bit OT labels are deterministically
expanded into P-256 field elements. These rules ensure that Beaver
triple generation, OT cross-multiplication, and correlated label
constructions produce identical field outputs across both peers.


The design follows MP-SPDZ practice: labels act as seeds to a
correlation-robust pseudorandom function whose output is interpreted
as an integer and reduced modulo the field prime. All expansions are
deterministic and domain separated.

### Label Structure

A label is a 128-bit value:

```go
struct Label {
    uint64 D0;    // least significant 64 bits
    uint64 D1;    // most significant 64 bits
}
```

Internally, labels are encoded as 16 bytes in big-endian order when
used as PRF keys.

```go
K = label.Bytes()    // 16 bytes, big-endian
```

### Purpose of Label Expansion

A label is never used directly as a field element.
Instead, each label represents correlated randomness used in:

 - Beaver triple generation
 - CrossMultiplyViaOT message encoding
 - SPDZ secret-sharing of preprocessed values

Mapping labels to field elements must satisfy:

 - deterministic across peers
 - uniform modulo p (PRF output reduced mod p)
 - domain-separated for different usages
 - consistent for all bit-chunk expansions

### PRF Definition

The expansion function uses AES-128 in counter mode (CTR) as a PRF.

Each label is treated as the AES-128 key. Each expansion uses:

```
PRF_K(domain || counter)
```

where `domain` is a one-byte domain-separation constant, and `counter`
is a 32-bit counter field.

**AES Mode**

 - AES-128 encryption is used directly.
 - No IV or chaining is required beyond the domain and counter fields.
 - The input block for AES is:

```
input_block = domain_byte || counter_be_32 || 11 zero bytes
```

This produces exactly one AES block (128 bits).

**Domain separation**

Each logical usage must use a different domain code:

```go
DomainExpandField        = 0x01
DomainExpandChunk        = 0x02
DomainExpandLabelOT      = 0x03
```

Only `DomainExpandField` and `DomainExpandChunk` are required for this
protocol, but the scheme leaves space for future extensions.

**Expand(label) to a FieldElement**

This function produces a single GF(p) element from a 128-bit label.

1. Form AES key:

```
K = label.Bytes()     // 16 bytes
```

2. Compute:

```
block = AES_128_Encrypt(K, [DomainExpandField || 0x00000000 || 11×0x00])
```

3. Interpret `block` as a 128-bit big-endian integer X.

4. Convert to a 32-byte value by left-padding with zeros:

```
padded = (16 zero bytes) || block
```

5. Convert to integer:

```
Z = big.Int(padded)   // big-endian
```

6. Reduce modulo field prime:

```
fe = Z mod p256
```

7. Return

```
FieldElement{v: fe}
```

**Pseudocode**

```go
func ExpandLabelToField(label Label) *FieldElement {
    K := label.Bytes()  // 16 bytes

    var in [16]byte
    in[0] = DomainExpandField
    // in[1..4] is counter (0)
    // in[5..15] = zero

    block := aes128Encrypt(K, in[:]) // 16 bytes

    padded := make([]byte, 32)
    copy(padded[16:], block)

    Z := new(big.Int).SetBytes(padded)
    Z.Mod(Z, fieldModP)

    return &FieldElement{v: Z}
}
```

### ExpandLabels(label[ ]) for Chunked Messages

Bitwise OT messages encode field elements as arrays of multiple labels.
Each label chunk must be expanded and combined in the correct order.

Let a field element be encoded as:

```
chunks: [Label_0, Label_1, ..., Label_{n-1}]
```

Each label chunk produces 128 output bits.

**ExpandLabels algorithm**

1. For each chunk `i`, compute:

```
block_i = AES_128_Encrypt(K_i, [DomainExpandChunk || counter=i || zero padding])
```

2. Concatenate

```
concat = block_0 || block_1 || ... || block_{n-1}
```

3. If concat has fewer than 32 bytes, left-pad with zeros.
4. Interpret as big-endian integer X.
5. Reduce modulo p256.
6. Return the result as a FieldElement.

**Pseudocode**

```go
func ExpandChunksToField(chunks []Label) *FieldElement {
    buf := make([]byte, 0, len(chunks)*16)

    for i, lab := range chunks {
        K := lab.Bytes()

        var in [16]byte
        in[0] = DomainExpandChunk
        binary.BigEndian.PutUint32(in[1:5], uint32(i))

        block := aes128Encrypt(K, in[:])
        buf = append(buf, block...)
    }

    // Ensure 32 bytes minimum
    if len(buf) < 32 {
        padded := make([]byte, 32)
        copy(padded[32-len(buf):], buf)
        buf = padded
    }

    Z := new(big.Int).SetBytes(buf)
    Z.Mod(Z, fieldModP)

    return &FieldElement{v: Z}
}
```

### Security Notes

 - AES-128 with label-as-key gives correlation robustness as long as
   labels are fresh and random.
 - Domain separation ensures that field-element expansion, chunk
   expansion, and OT masks cannot collide.
 - The modulo reduction produces outputs statistically close to
   uniform in GF(p).

### Interoperability Requirements

Both peers must implement:

 - identical AES-128 encryption
 - identical domain separation
 - identical padding, concatenation, and reduction rules
 - identical mapping from labels to big-endian byte arrays
 - identical conversion to FieldElement values

Any deviation breaks joint triple generation and invalidates SPDZ
correctness.

### Summary

The PRF expansion rules define:

 - Expand one label to a field element
 - Expand an array of labels to a field element
 - Deterministic AES-128-CTR-style PRF with domain separation
 - Big-endian interpretation and reduction modulo P-256
 - 32 byte canonical encoding for all SPDZ field values

These definitions make label-based correlated randomness fully
deterministic and interoperable across peers and across languages.

## Coding Style

The code follows idiomatic Go coding guidelines. All errors are
checked and handled or passed to the caller.

When feasible, the implementation adds protocol consistency checks to
verify protocol state and elements are as expected. If any deviations
are found, the code clearly reports the error to help debugging.

## Peer Function High-Level Pseudocode

```text
// High-level Peer protocol for semi-honest SPDZ P-256 point addition
func Peer(oti, id, conn, xInput, yInput):

    // ---------------------------------------------------------------
    // Phase 0: Initialization
    // ---------------------------------------------------------------
    // Assign OT role based on peer ID
    if id == 0:
        oti.InitSender(conn)
    else:
        oti.InitReceiver(conn)

    // Local RNG for Beaver triple generation and output sharing
    rng := NewSecureRNG()


    // ---------------------------------------------------------------
    // Phase 1: Preprocessing — OT-based Beaver Triple Generation
    // ---------------------------------------------------------------
    // Generate Beaver triples (a, b, c) with c = a*b mod p_spdz
    // Semi-honest: no consistency checks, no MACs.
    //
    // params specifies the number of Beaver triples needed for the
    // ECPointAdd_SPDZ implementation. Its exact value is defined inside
    // spdz.go and depends on the chosen formula (affine or projective).
    triples := GenerateBeaverTriplesSemiHonest(oti, conn, params)


    // ---------------------------------------------------------------
    // Phase 2: Secret-sharing plaintext inputs
    // ---------------------------------------------------------------
    // Each peer provides its own plaintext input point.
    // xInput, yInput are full coordinates of P (peer 0) or Q (peer 1).
    // SecretShareInput returns the local SPDZ additive shares of the
    // inputs.
    //
    // SecretShareInput(x,y) selects a random FieldElement r locally,
    // sends r to the other peer, and returns (x - r mod p). Each peer
    // does this independently.

    if id == 0:
        (Px_share, Py_share) := SecretShareInput(xInput, yInput)
        // For the missing point Q, the peer contributes "no input"
        (Qx_share, Qy_share) := SecretShareInput(0, 0)   // Peer 0 provides no Q input

    else:
        (Qx_share, Qy_share) := SecretShareInput(xInput, yInput)
        (Px_share, Py_share) := SecretShareInput(0, 0)   // Peer 1 provides no P input

    // After both peers run SecretShareInput, their shares combine as:
    // Px = Px_share(peer0) + Px_share(peer1) mod p256
    // Py = Py_share(peer0) + Py_share(peer1) mod p256
    // Likewise for Qx, Qy.


    // ---------------------------------------------------------------
    // Phase 3: Online SPDZ Computation — Compute R = P + Q
    // ---------------------------------------------------------------
    // ECPointAdd_SPDZ performs P-256 field ops inside SPDZ:
    // additions, multiplications, inversions (if using affine),
    // or projective formulas.

    (Rx_share, Ry_share) := ECPointAdd_SPDZ(
                                Px_share, Py_share,
                                Qx_share, Qy_share,
                                triples)


    // ---------------------------------------------------------------
    // Phase 4: Convert SPDZ outputs to field integers
    // ---------------------------------------------------------------
    // Reduce modulo P-256 field prime and obtain integer values inside SPDZ
    Rx := ReduceModP256(Rx_share)
    Ry := ReduceModP256(Ry_share)

    // Reveal Rx, Ry inside SPDZ to obtain public integers rX, rY.
    // (Semi-honest: openings require no MAC checks)
    rX := Open(Rx)
    rY := Open(Ry)


    // ---------------------------------------------------------------
    // Phase 5: Re-share outputs as uint256 additive shares
    // ---------------------------------------------------------------
    // Each peer creates random 256-bit shares and exchanges the complementary share.
    // Convert integers to 32-byte big-endian buffers before sending.

    if id == 0:
        // Peer 0 chooses random shares
        sX := rng.Uint256()
        sY := rng.Uint256()

        // Complement shares computed modulo 2^256
        oX := (rX - sX) mod 2^256
        oY := (rY - sY) mod 2^256

        // Send complement shares to peer 1
        conn.SendData(oX.FillBytes(32))
        conn.SendData(oY.FillBytes(32))
        conn.Flush()

        // Receive peer 1's complement shares
        _ = conn.ReceiveData()
        _ = conn.ReceiveData()

        // Local output = this peer's random shares
        xOut = sX
        yOut = sY

    else:
        // Peer 1 chooses random shares
        sX := rng.Uint256()
        sY := rng.Uint256()

        // Complement shares
        oX := (rX - sX) mod 2^256
        oY := (rY - sY) mod 2^256

        // Receive peer 0's complement shares
        _ = conn.ReceiveData()
        _ = conn.ReceiveData()

        // Send complement shares
        conn.SendData(oX.FillBytes(32))
        conn.SendData(oY.FillBytes(32))
        conn.Flush()

        // Local output = this peer's random shares
        xOut = sX
        yOut = sY


    // ---------------------------------------------------------------
    // Phase 6: Return the additive result shares
    // ---------------------------------------------------------------
    return (xOut, yOut)
```

The Beaver triple generation is specified in the
`ctx-beaver-triple.md` file.

The `CrossMultiplyViaOT` is implemented as follows:

```
// CrossMultiplyViaOT(oti, conn, v, b_bits, bitlen)
// Roles:
//  - id == 0 : "sender" (knows v)
//  - id == 1 : "receiver" (knows b_bits)
// Returns:
//  - (shareSender, shareReceiver) additive shares of v * b mod p_spdz
//
// Note: All heavy crypto (PRF, ExpandLabels, SplitFieldToLabels) is provided
// by spdz.go. This pseudocode shows exact message contents and masking logic.

func CrossMultiplyViaOT(oti, conn, v, b_bits[], bitlen):

    // Choose label chunk width and compute chunks per field element
    label_bits := 128                      // size of Label in bits
    field_bits := BitLength(p_spdz)        // e.g., 256
    chunks := ceil(field_bits / label_bits)

    // Pre-allocate arrays
    // For each bit k we will have a Wire carrying two messages,
    // each message may be represented as `chunks` labels.
    otWires := make([]Wire, bitlen)       // one Wire per bit, each Wire contains 2 * chunks labels conceptually
    flags := make([]bool, bitlen)         // receiver's choice bits

    // Sender-side random masks (field elements) for each bit
    // Sender computes r_k for each bit; its share will be -sum r_k
    if id == 0:
        r := make([]FieldElement, bitlen)
        for k in 0 .. bitlen-1:
            r[k] = rng.FieldElement()
    end if

    // Build OT messages (batched) ----------------------------------------------------------------

    // For performance, we will build the pair of messages (m0_k, m1_k) per bit, and encode each
    // field element message as an array of `chunks` labels via SerializeFieldToLabels.

    if id == 0:
        // Sender constructs wires
        for k in 0 .. bitlen-1:
            // m0_k = r[k]                     (field element)
            // m1_k = r[k] + v * (2^k mod p_spdz)
            two_pow_k := Pow2Mod(k, p_spdz)                  // compute 2^k mod p_spdz
            addend := (v * two_pow_k) mod p_spdz
            m0 := r[k]                                       // field element
            m1 := (r[k] + addend) mod p_spdz                 // field element

            // Serialize field elements into label chunks
            labels_m0 := SerializeFieldToLabels(m0, chunks)  // returns [Label] length=chunks
            labels_m1 := SerializeFieldToLabels(m1, chunks)

            // Compose Wire: each Wire holds the pair (labels_m0, labels_m1)
            // Implementation detail: your Wire struct can be extended to hold slices of Labels:
            // Wire{ L0: labels_m0, L1: labels_m1 }.
            otWires[k] := Wire{ L0: labels_m0, L1: labels_m1 }
        end for

        // Send all wires in one batch (or several batches if bitlen large)
        oti.Send(otWires)

        // After sending, compute local sender share:
        // shareSender = - sum_k r[k]  (mod p_spdz)
        shareSender := 0
        for k in 0 .. bitlen-1:
            shareSender = (shareSender - r[k]) mod p_spdz
        end for

        // The receiver will compute shareReceiver by expanding chosen labels and summing them.
        // The function returns (shareSender, shareReceiver_placeholder).
        // The actual shareReceiver will be filled when receiver code executes and both sides may exchange nothing
        // because the receiver already obtained its labels via OT.
        return (shareSender, nil)   // receiver's share will be computed on its side and used jointly
    else:
        // Receiver constructs flags array (bits of b)
        for k in 0 .. bitlen-1:
            flags[k] := b_bits[k] == 1
        end for

        // Prepare receive buffer: for each bit we will receive a Label slice of length=chunks
        receivedLabels := make([][]Label, bitlen)

        // Perform batched OT receive:
        // oti.Receive expects flags[] and returns chosen outputs; design of API must support multi-label wires.
        oti.Receive(flags, receivedLabels)

        // For each chosen label chunk array, Expand labels into field element and sum:
        shareReceiver := 0
        for k in 0 .. bitlen-1:
            labels_k := receivedLabels[k]                    // array of `chunks` Label
            mk := ExpandLabels(labels_k)                     // Convert labels->field element
            shareReceiver = (shareReceiver + mk) mod p_spdz
        end for

        // Receiver returns (nil, shareReceiver) for the caller; the sender returned its share earlier.
        return (nil, shareReceiver)
    end if

// End of CrossMultiplyViaOT
```
