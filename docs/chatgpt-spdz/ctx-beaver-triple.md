
# Beaver Triple Generation for Semi-Honest SPDZ  
### Using OT Correlation and AES-128 PRF Label Expansion

This document defines the generation of Beaver triples for a semi-honest two-party SPDZ protocol.  
Triple generation uses:

- 1-out-of-2 Oblivious Transfer (OT)
- 128-bit labels with AES-128-based PRF expansion
- Deterministic P-256 finite field arithmetic
- CrossMultiplyViaOT for cross terms

The specification is fully implementable and consistent with the SPDZ field and PRF definitions.

---

## 1. Triple Structure

A Beaver triple consists of three field values:

```
(a, b, c) where c = a * b mod p256
```

Each peer holds additive shares:

```
Peer 0: (a0, b0, c0)
Peer 1: (a1, b1, c1)
```

with

```
a = a0 + a1 mod p256
b = b0 + b1 mod p256
c = c0 + c1 mod p256
```

Peer 0 is the OT sender.  
Peer 1 is the OT receiver.

---

## 2. Dependencies

Beaver triple generation depends on:

1. **Label expansion**  
   `ExpandLabelToField(label) -> FieldElement`  
   defined using AES-128 PRF with domain separation.

2. **FieldElement arithmetic**  
   implemented using `math/big` modulo the P-256 prime.

3. **CrossMultiplyViaOT**  
   used to compute cross terms `a0*b1` and `a1*b0`.

---

## 3. Stage 1: Sampling Additive Shares of a

### Step 1: Peer 0 samples randomness

```go
A0_label := NewRandomLabel()
a0 := ExpandLabelToField(A0_label)
deltaA_label := NewRandomLabel()

L0 = A0_label
L1 = XOR_Label(A0_label, deltaA_label)
```

Peer 0 sends the OT wire:

```
Wire{ L0, L1 }
```

### Step 2: Peer 1 receives correlated value

Peer 1 chooses a random bit:

```go
fA := random bit
```

Runs OT receive:

```go
A1_label := ReceiveWire(fA)
a_raw := ExpandLabelToField(A1_label)
```

### Step 3: Final a-shares

We define:

```
a := a_raw
```

Shares:

```
Peer 0: a0
Peer 1: a1 = a_raw - a0 mod p
```

Peer 0 sends `a0` to Peer 1 as a 32 byte big-endian field element.  
This value is uniformly random and leaks no OT information.

---

## 4. Stage 2: Sampling Additive Shares of b

Identical to the steps for a:

### Peer 0:

```go
B0_label := NewRandomLabel()
b0 := ExpandLabelToField(B0_label)
deltaB_label := NewRandomLabel()

L0b = B0_label
L1b = XOR_Label(B0_label, deltaB_label)
SendWire(Wire{L0b, L1b})
```

### Peer 1:

```go
fB := random bit
B1_label := ReceiveWire(fB)
b_raw := ExpandLabelToField(B1_label)
```

Shares:

```
Peer 0: b0
Peer 1: b1 = b_raw - b0 mod p
```

Peer 0 sends `b0` to Peer 1 as 32 bytes.

---

## 5. Stage 3: Computing c = a * b

We use:

```
c = a0*b0 + a0*b1 + a1*b0 + a1*b1
```

### 5.1 Local products

```
Peer 0: local0 = a0 * b0
Peer 1: local1 = a1 * b1
```

### 5.2 Cross term a0*b1

Peer 0 supplies `a0`.  
Peer 1 supplies the bits of `b1`.

```
(cross0_sender, cross0_receiver) =
    CrossMultiplyViaOT(oti, conn, value = a0, bits = b1_bits)
```

### 5.3 Cross term a1*b0

```
(cross1_sender, cross1_receiver) =
    CrossMultiplyViaOT(oti, conn, value = a1, bits = b0_bits)
```

### 5.4 Final c-shares

```
Peer 0: c0 = local0 + cross0_sender + cross1_sender
Peer 1: c1 = local1 + cross0_receiver + cross1_receiver
```

All arithmetic is modulo p256.

We have:

```
c0 + c1 mod p = a*b mod p
```

---

## 6. Full Triple Generation Loop

For N triples:

```
triples = []

for i in 1..N:
    generate a0,a1 through OT
    generate b0,b1 through OT
    compute c0,c1 through CrossMultiplyViaOT
    append (a0,b0,c0) or (a1,b1,c1) to local triple list

return triples
```

Each triple uses fresh labels and fresh OT bits.

---

## 7. Security Notes

- Only standard OT leakage applies; the protocol is semi-honest secure.
- Peer 0 learns nothing about the choice bits fA, fB.
- Peer 1 learns nothing about the correlation deltas.
- a0 and b0 are uniformly random field elements and leak no structure.
- Label PRF ensures deterministic, collision-resistant output mapping.

---

## 8. Implementer Requirements

- Use exactly the AES-128 PRF domain definitions.  
- Use the 32 byte big-endian field encoding for all transmissions.  
- Use the FieldElement operations defined in the SPDZ Field Arithmetic document.  
- Ensure CrossMultiplyViaOT uses the same chunking and label-expansion rules.  
- Never shortcut reduction; all values must be canonical modulo p256.

