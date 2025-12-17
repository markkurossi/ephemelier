# VOLE-from-OT Protocol Documentation
A Research-Grade Description of the Algorithm Implemented in `vole.go`

---

## 1. Introduction

This document provides a *research-grade* description of the **OT-based VOLE** protocol implemented in `vole.go`.
This VOLE construction is the classical approach obtained by combining:

1. **IKNP OT Extension**
2. **Pseudorandom correlation expansion using PRGs (AES/ChaCha)**
3. **A linear masking relation**
4. **Communication of masked field elements**

This protocol produces a 2-party **VOLE correlation**:

- Sender obtains:
  **(a₁,…,a_m)**, **(r₁,…,r_m)**
- Receiver obtains:
  **(x₁,…,x_m)**, **(a₁x₁+r₁,…,a_mx_m+r_m)**

All operations are over a field **𝔽ₚ** (in code using `math/big.Int` but should ideally use a fixed-size 256-bit field).

The protocol is semi-honest secure and follows the classical OLE/VOLE-from-OT paradigm first seen in:

- IKNP (2003) — foundational OT extension
- ALSZ (2013/2015) — practical OT extension
- Standard OLE-from-OT constructions (IKO, Hazay–Lindell, Scholl’s VOLE lectures)

---

## 2. Problem Definition

Given two parties:

### Sender (S):
Inputs:
- Field elements **a₁,…,a_m ∈ 𝔽ₚ**

Wants to receive:
- Random field elements **r₁,…,r_m**

### Receiver (R):
Inputs:
- Field elements **x₁,…,x_m ∈ 𝔽ₚ**

Wants to receive:
- Values **uᵢ = aᵢ xᵢ + rᵢ mod p**

Thus together they obtain the VOLE correlation:
- S learns: (aᵢ, rᵢ)
- R learns: (xᵢ, uᵢ)
- Relationship: uᵢ − rᵢ = aᵢ · xᵢ (over the field)

No additional information is revealed to either party.

---

## 3. High-Level Protocol Overview

The protocol builds on **m executions of correlated Oblivious Transfer**, realized through:

1. **IKNP-style OT extension** generates many correlated random seeds:
    - Sender gets two PRG seeds per OT (label₀ᵢ, label₁ᵢ)
    - Receiver gets one seed according to its choice xᵢ ∈ {0,1}

2. Each PRG seed expands into a large pseudorandom field element using AES or ChaCha.

3. Using these expanded values, sender constructs:
    - rᵢ = PRG(label₀ᵢ)
    - tᵢ = PRG(label₁ᵢ)

4. Receiver obtains:
    - yᵢ = PRG(label_{xᵢ}) — pseudorandom but correlated with sender’s values.

5. Sender computes:
    ```
    uᵢ = rᵢ + aᵢ·(tᵢ − rᵢ)  mod p
    ```

6. Receiver receives uᵢ and knows xᵢ, thus recovers:
    ```
    (tᵢ − rᵢ) = 1 if xᵢ = 1
               0 if xᵢ = 0
    ```
    leading to:
    ```
    uᵢ = aᵢ xᵢ + rᵢ
    ```

This establishes the required VOLE relation.

---

## 4. Detailed Protocol Specification

Let:

- m: the number of VOLE instances
- p: the field modulus
- PRG: a pseudorandom generator (AES-CTR or ChaCha20)

Notation:
- PRG(s): PRG expansion of seed *s* into a field element
- ⊕: XOR of binary vectors
- mod p: field arithmetic

---

### 4.1 IKNP OT Extension Phase

Perform **m** 1-out-of-2 OTs using IKNP in correlated mode.

**Sender obtains:**
- Two PRG seeds per OT:
  (Lᵢ⁰, Lᵢ¹)

**Receiver obtains:**
- One PRG seed Lᵢ^{xᵢ} based on its input bit xᵢ.

This gives correlated randomness:
- If xᵢ=0, both parties hold Lᵢ⁰
- If xᵢ=1, sender has both Lᵢ⁰ and Lᵢ¹; receiver has Lᵢ¹

The security is inherited directly from IKNP.

---

### 4.2 PRG Expansion Phase

For every i:

Sender computes:
```
rᵢ = PRG(Lᵢ⁰) mod p
tᵢ = PRG(Lᵢ¹) mod p
```

Receiver computes:
```
yᵢ = PRG(Lᵢ^{xᵢ}) mod p
```

By pseudorandomness of the PRG, all rᵢ, tᵢ, yᵢ are computationally indistinguishable from uniform.

---

### 4.3 VOLE Mask Preparation

Receiver sends **u-vector** entries computed by sender:
```
uᵢ = rᵢ + aᵢ·(tᵢ − rᵢ)  mod p
```

This ensures:
- If xᵢ = 0, then tᵢ - rᵢ = 0 → uᵢ = rᵢ
- If xᵢ = 1, then tᵢ - rᵢ = 1*(some correlated randomness) → uᵢ = rᵢ + aᵢ

Receiver, knowing xᵢ, obtains:
```
uᵢ = rᵢ + aᵢ xᵢ mod p
```

Sender knows rᵢ, receiver knows xᵢ and uᵢ.

Thus the VOLE correlation is complete.

---

## 5. Correctness Proof

Given the construction:

```
uᵢ = rᵢ + aᵢ·(tᵢ − rᵢ)
```

Case 1: **xᵢ = 0**
Receiver obtains yᵢ = rᵢ
Then tᵢ − rᵢ = 0 (hidden to receiver), and:

```
uᵢ = rᵢ = aᵢ·0 + rᵢ
```

Case 2: **xᵢ = 1**
Receiver obtains yᵢ = tᵢ
Then tᵢ − rᵢ = 1*(tᵢ − rᵢ), and:

```
uᵢ = rᵢ + aᵢ = aᵢ·1 + rᵢ
```

Thus in all cases:
```
uᵢ = aᵢ xᵢ + rᵢ mod p
```

---

## 6. Security Argument (Semi-Honest)

### Sender Privacy
Receiver learns only:
- xᵢ
- uᵢ = aᵢxᵢ + rᵢ
- yᵢ = PRG(Lᵢ^{xᵢ})

Given rᵢ is pseudorandom, uᵢ hides aᵢ perfectly.
Thus receiver learns nothing additional about aᵢ.

### Receiver Privacy
Sender learns rᵢ, tᵢ but does not know which seed the receiver obtained.
Thus sender cannot distinguish whether receiver chose Lᵢ⁰ or Lᵢ¹.

### Underlying Assumptions
- PRG security (AES/ChaCha indistinguishability)
- IKNP OT security
- No key reuse accident
- Fresh seeds per VOLE execution

---

## 7. Engineering Notes & Improvements

### Recommended improvements:
- Replace BigInt with fixed 32-byte field elements
- Use HKDF for all PRG keys
- Zero buffers in long-running servers
- Use bufPool throughout hot paths
- Validate nonce/key uniqueness invariants

These improvements dramatically increase performance and security in practice.

---

## 8. Summary

This protocol is a **classical OT-based VOLE**, built from:
- IKNP OT extension
- PRG expansion of correlated seeds
- linear masking via uᵢ = rᵢ + aᵢxᵢ

It is secure in the semi-honest model and extremely practical—especially with fast AES-based PRGs.

The algorithm in *vole.go* is a faithful implementation of this widely-taught construction.
