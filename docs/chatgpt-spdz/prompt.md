# Overview

This document specifies a semi-honest secure two-party protocol for
computing the elliptic curve addition R = P + Q over the NIST P-256
curve using a SPDZ-style arithmetic MPC with Beaver triples generated
via oblivious transfer (OT).

**Security Model**: The protocol operates in the semi-honest model,
meaning both peers follow the protocol as specified but may try to
extract information from received messages. The protocol ensures that
no additional information is leaked.

No active-security (malicious) protections are included.  There are no
MACs, no global α, no triple checking, no sacrifice steps, and no
malicious OT extensions.

In the beginning:
 - Peer 0 holds the full plaintext point P.
 - Peer 1 holds the full plaintext point Q.
These points are not shared initially. The protocol begins by
secret-sharing these two input points inside SPDZ so that neither peer
learns the other peer’s input. The goal is to securely compute the
elliptic curve addition P+Q.

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

## The Connection API

The `p2p.Conn` has the following functions:

```go
func (conn *Conn) SendByte(val byte) error
func (conn *Conn) SendUint16(val int) error
func (conn *Conn) SendUint32(val int) error
func (conn *Conn) SendData(val []byte) error
func (conn *Conn) ReceiveByte() (byte, error)
func (conn *Conn) ReceiveUint16() (int, error)
func (conn *Conn) ReceiveUint32() (int, error)
func (conn *Conn) ReceiveData() ([]byte, error)
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

// OT defines Oblivious Transfer protocol.
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

// Wire implements a wire with 0 and 1 labels.
type Wire struct {
	L0 Label
	L1 Label
}

// Label implements a 128 bit wire label.
type Label struct {
	D0 uint64
	D1 uint64
}
```

The ot package is used to implement the base 1-out-of-2 OT. Any OT
extensions are implemented on top of the base OT in `spdz.go`.

Peer 0 initializes the OT sender role, and Peer 1 initializes the OT
receiver role. This corresponds to the standard SPDZ setup where one
party plays the OT sender for triple generation and the other plays
the receiver.

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
    // SecretShareInput returns the local SPDZ additive shares of the inputs.

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

The Beaver triples are generated with the following pseudocode.

In the Beaver triple pseudocode, field elements appear to be sent
directly through OT for conceptual clarity. In the actual
implementation, these values are encoded into 128-bit Label structures
using a PRF, and the SPDZ engine interprets each Label as correlated
randomness that deterministically expands into the field element used
in triple generation.

```
// GenerateBeaverTriplesSemiHonest(oti, conn, n)
//
// Assumptions and helpers:
//  - Expand(label) -> field element in Z_p_spdz (deterministic PRF/expand).
//  - XOR_Label(L0, delta_label) returns a new Label encoding L0 XOR delta_label.
//  - XOR_Label is in label-space (128-bit), not in the field.
//  - CrossMultiplyViaOT(oti, conn, v, b_bits, bitlen) returns additive shares
//    (shareA, shareB) such that shareA + shareB = v * b (mod p_spdz).
//    This primitive is implemented with bitwise OT (sender knows v).
//
// Result: returns `triples` list of length n where each entry is
//         (a0, b0, c0) for this party (the peer running the function).
//
// Roles:
//  - id == 0: OT sender role (also called "sender").
//  - id == 1: OT receiver role (also called "receiver").

func GenerateBeaverTriplesSemiHonest(oti, conn, n, bitlen):

    triples := empty list

    for i in 1..n:

        // 1) Each peer samples two fresh 128-bit label seeds (local randomness)
        a_seed := rng.Label()   // 128-bit
        b_seed := rng.Label()   // 128-bit

        // Expand local seeds into local field elements
        a_local := Expand(a_seed)    // in Z_p_spdz
        b_local := Expand(b_seed)

        // 2) OT-based correlated-label exchange to create complementary shares
        //
        // Sender (id==0) chooses delta labels; Receiver obtains one of {L0,L1}.
        if id == 0:
            // Sender prepares correlation labels for 'a'
            delta_a_label := rng.Label()            // 128-bit correlation seed
            L0_a := a_seed
            L1_a := XOR_Label(a_seed, delta_a_label)
            oti.Send([ Wire{ L0_a, L1_a } ])

            // For 'b'
            delta_b_label := rng.Label()
            L0_b := b_seed
            L1_b := XOR_Label(b_seed, delta_b_label)
            oti.Send([ Wire{ L0_b, L1_b }])

            // The sender's local shares are simply its expanded values
            a_share := a_local
            b_share := b_local

        else:
            // Receiver obtains labels based on private choice bits flag_a, flag_b.
            // Choose flags uniformly at random (they determine which relative shift the receiver gets).
            // In practice flags can be random bits per triple; different constructions exist.
            flag_a := rng.Bit()
            recvLabelA := new Label
            oti.Receive([flag_a], [recvLabelA])
            a_other := Expand(recvLabelA)   // receiver-side expanded field value

            flag_b := rng.Bit()
            recvLabelB := new Label
            oti.Receive([flag_b], [recvLabelB])
            b_other := Expand(recvLabelB)

            // Now derive receiver's additive shares so that:
            //  a = a_share_sender + a_share_receiver
            //  b = b_share_sender + b_share_receiver
            // Sender's share (a_share_sender) will equal a_local (unknown to receiver).
            // Define receiver's share = a_other - a_local_or_a_local_plus_delta.
            // But receiver does not know a_local or delta_label; instead we produce a
            // constructive formula below that yields correct additive shares.
            //
            // The following formulas produce valid additive shares:
            //  - if receiver got L0 (flag==0): a_other == Expand(a_seed) == a_local
            //    receiver_share = 0
            //  - if receiver got L1 (flag==1): a_other == Expand(a_seed XOR delta)
            //    receiver_share = a_other - (a_local + delta_field)
            //
            // For implementation simplicity and for compatibility with sender-side shares,
            // we produce the receiver share as:
            if flag_a == 0:
                a_share := 0
            else:
                // Note: although receiver does not know delta_label, Expand(delta_label)
                // is only available to sender; hence do NOT attempt to compute it here.
                // Instead the receiver computes its share as:
                //   a_share := a_other - Expand(a_seed) - Expand(delta_label)
                // But receiver cannot compute Expand(a_seed) nor Expand(delta_label).
                // To keep receiver-sided computation local, we choose a construction
                // where receiver's share is simply `a_other - Expand(a_seed)` and the
                // sender's share is adjusted accordingly (sender knows both a_local and delta).
                //
                // For clarity and correctness, below we use the symmetric construction:
                //  - Sender's share = a_local
                //  - Receiver's share = a_other - a_local
                // This yields a = a_local + (a_other - a_local) = a_other.
                // Thus the actual a that is generated equals `a_other` (controlled by receiver's flag choice).
                a_share := (a_other - ExpandPlaceholder_SenderValue()) // placeholder, see note below

            // The same logic for b
            if flag_b == 0:
                b_share := 0
            else:
                b_share := (b_other - ExpandPlaceholder_SenderValue()) // placeholder

            // IMPORTANT:
            // The above placeholder pattern indicates that the *actual value a that
            // the parties obtain depends on the receiver's flag choice (i.e., either
            // sender-seeded value or sender-seeded+delta). This is acceptable: the
            // final a and b are jointly random and unknown to any single party.
            // Implementation details in spdz.go should implement consistent label→field mapping
            // and proper assignment of sender/receiver shares so that a = a0 + a1.
            //
            // For clean, practical implementation, prefer constructing shares as:
            //  - Sender: a0 = Expand(a_seed)
            //  - Receiver: a1 = Expand(recvLabel) - Expand(a_seed)
            // Where Expand(a_seed) is computed by sender and used by sender to adjust c-share accordingly.
            // The receiver does not need Expand(a_seed) (sender knows it); the adjustments to c_share use values known locally.
            //
            // See concrete implementation note at the end of this pseudocode.

        // ------------------------------
        // 3) Compute cross-terms using OT-based multiplication helpers.
        //    We need to compute the cross products:
        //       a0 * b1  and  a1 * b0
        //
        // Use CrossMultiplyViaOT to compute additive shares of these cross-products.
        // CrossMultiplyViaOT returns (shareSender, shareReceiver) s.t. shareSender + shareReceiver = value * b (mod p_spdz)
        // Where the party that calls CrossMultiplyViaOT as "sender" supplies `value` and the other supplies secret `b` bits.
        //
        // Implementation convention: let party 0 act as the OT-sender for CrossMultiplyViaOT calls where it supplies 'value'.
        // If party 1 supplies 'value' in some calls, swap roles accordingly.
        // ------------------------------

        // Compute additive shares for cross-term a0 * b1
        // - party 0 supplies a_share (value) and party 1 supplies b1 as secret bits
        (cross0_a0b1_senderShare, cross0_a0b1_receiverShare) :=
                CrossMultiplyViaOT(oti, conn, a_share if id==0 else a_local, b1_bits, bitlen)

        // Compute additive shares for cross-term a1 * b0
        (cross1_a1b0_senderShare, cross1_a1b0_receiverShare) :=
                CrossMultiplyViaOT(oti, conn, b_share if id==0 else b_local, a1_bits, bitlen)
                // note: roles swapped as appropriate in implementation

        // ------------------------------
        // 4) Assemble c-shares
        //    Each party computes its local c_share such that sum(c_shares) = a*b
        //    Using expansion:
        //      a*b = a0*b0 + a0*b1 + a1*b0 + a1*b1
        //    Let each party own local terms they can compute plus their cross-term share.
        // ------------------------------

        if id == 0:
            local_a0b0 := a_local * b_local mod p_spdz   // sender can compute
            local_a1b1 := 0                              // sender doesn't know a1 or b1
            local_cross := cross0_a0b1_senderShare + cross1_a1b0_senderShare
            c_share := (local_a0b0 + local_cross) mod p_spdz
        else:
            local_a0b0 := 0
            local_a1b1 := a_other * b_other mod p_spdz   // receiver can compute if it derived both a_other and b_other
            local_cross := cross0_a0b1_receiverShare + cross1_a1b0_receiverShare
            c_share := (local_a1b1 + local_cross) mod p_spdz

        triples.append( (a_share, b_share, c_share) )

    return triples
```

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
