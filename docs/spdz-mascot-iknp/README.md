# SPDZ Online Phase: Detailed Breakdown from Each Peer's Perspective

## Initial State

### Peer 1 has:
- **Private input**: `(pub1X, pub1Y)` - their EC point
- **Secret**: `α₁` (MAC key share)
- **Preprocessed**: 3 multiplication triples with their shares

### Peer 2 has:
- **Private input**: `(pub2X, pub2Y)` - their EC point
- **Secret**: `α₂` (MAC key share)
- **Preprocessed**: 3 multiplication triples with their shares

### Neither peer knows:
- The other peer's input point
- The global MAC key `α = α₁ + α₂`
- The full triple values (only their shares)

---

## Step 1: Secret Sharing Phase

### Peer 1 shares their point:

```go
x1Share1, x1Share2 := peer1.SecretShare(pub1X, peer2)
y1Share1, y1Share2 := peer1.SecretShare(pub1Y, peer2)
```

**What happens:**
- Peer 1 splits `pub1X` into `x1Share1` and `x1Share2` where:
  - `x1Share1 + x1Share2 = pub1X (mod P)`
- Peer 1 computes MACs: `MAC₁ + MAC₂ = α · pub1X`
- **Sends to Peer 2**: `x1Share2` and its MAC
- **Keeps**: `x1Share1` and its MAC

**After this:**
- **Peer 1 holds**: `⟨pub1X⟩₁ = (x1Share1, MAC₁)` and `⟨pub1Y⟩₁ = (y1Share1, MAC₁)`
- **Peer 2 holds**: `⟨pub1X⟩₂ = (x1Share2, MAC₂)` and `⟨pub1Y⟩₂ = (y1Share2, MAC₂)`

### Peer 2 shares their point:

```go
x2Share1, x2Share2 := peer2.SecretShare(pub2X, peer1)
y2Share1, y2Share2 := peer2.SecretShare(pub2Y, peer1)
```

Same process as above.

### After sharing both points:

| Peer 1 Holds (Private) | Peer 2 Holds (Private) |
|------------------------|------------------------|
| `⟨pub1X⟩₁`, `⟨pub1Y⟩₁` | `⟨pub1X⟩₂`, `⟨pub1Y⟩₂` |
| `⟨pub2X⟩₁`, `⟨pub2Y⟩₁` | `⟨pub2X⟩₂`, `⟨pub2Y⟩₂` |

**🔑 Key point**: Neither peer can reconstruct the other's original point!

---

## Step 2: Computing λ = (y2 - y1) / (x2 - x1)

### Substep 2a: Compute numerator = y2 - y1

**Each peer computes locally:**

```go
// Peer 1
numerator1 = y2Share1 - y1Share1 (mod P)
MAC₁_num = MAC₁_y2 - MAC₁_y1 (mod P)

// Peer 2
numerator2 = y2Share2 - y1Share2 (mod P)
MAC₂_num = MAC₂_y2 - MAC₂_y1 (mod P)
```

**✅ No communication needed!** Addition/subtraction is local.

### Substep 2b: Compute denominator = x2 - x1

Same as above - local computation only.

### Substep 2c: Open denominator

**Why?** We need to compute `1/(x2-x1)`, which requires the actual value.

```go
denomOpen, err := Open(denominator1, denominator2, peer1, peer2)
```

**📡 Communication:**
- **Peer 1 sends**: `denominator1.Value`, `denominator1.MAC`
- **Peer 2 sends**: `denominator2.Value`, `denominator2.MAC`
- **Both compute**: `denom = denominator1.Value + denominator2.Value (mod P)`
- **Both verify**: `MAC₁ + MAC₂ = α · denom`

**Result**: Both peers now know `x2 - x1` (but still don't know x1 or x2 individually!)

### Substep 2d: Compute λ = numerator · (1/denom)

```go
denomInv := ModInverse(denomOpen, P256Prime)
lambda1 := peer1.MultiplyConstant(numerator1, denomInv)
lambda2 := peer2.MultiplyConstant(numerator2, denomInv)
```

**Each peer locally:**
- Computes the modular inverse (both get same `denomInv` since they have same `denomOpen`)
- Multiplies their share by the public constant `denomInv`
- Updates their MAC accordingly

**✅ No communication needed!** Multiplying by public constant is local.

**After this:**
- **Peer 1 holds**: `⟨λ⟩₁` (share of λ)
- **Peer 2 holds**: `⟨λ⟩₂` (share of λ)
- **🔒 Neither knows the actual value of λ!**

---

## Step 3: Computing x3 = λ² - x1 - x2

### Substep 3a: Compute λ² (SECURE MULTIPLICATION)

```go
toOpen1, tripleIdx1 := peer1.Multiply(lambda1, lambda1)
toOpen2, _ := peer2.Multiply(lambda2, lambda2)
```

**Each peer locally (using Beaver triple):**
- Gets their share of triple: `(a, b, c)` where `c = a·b`
- Computes `ε = λ - a` and `δ = λ - b` (local)
- Prepares to share: `ε.Value` and `δ.Value`

**📡 Communication:**
- **Peer 1 sends**: `ε₁`, `δ₁`
- **Peer 2 sends**: `ε₂`, `δ₂`
- **Both reconstruct**:
  ```go
  ε = ε₁ + ε₂ (mod P)
  δ = δ₁ + δ₂ (mod P)
  ```

**Each peer completes multiplication locally:**

```go
lambdaSqComplete1 := peer1.CompleteMult(tripleIdx1, epsilonOpen, deltaOpen)
lambdaSqComplete2 := peer2.CompleteMult(tripleIdx1, epsilonOpen, deltaOpen)
```

Formula:
- Peer 1: `λ² = c₁ + ε·b₁ + δ·a₁ + ε·δ`
- Peer 2: `λ² = c₂ + ε·b₂ + δ·a₂`

**After this:**
- **Peer 1 holds**: `⟨λ²⟩₁` (share of λ²)
- **Peer 2 holds**: `⟨λ²⟩₂` (share of λ²)

### Substep 3b: Compute x3 = λ² - x1 - x2

```go
x3Share1 = lambdaSqComplete1 - x1Share1 - x2Share1 (mod P)
x3Share2 = lambdaSqComplete2 - x1Share2 - x2Share2 (mod P)
```

**✅ No communication!** Just local subtraction.

---

## Step 4: Computing y3 = λ(x1 - x3) - y1

### Substep 4a: Compute x1 - x3

```go
x1MinusX3_1 = x1Share1 - x3Share1 (mod P)
x1MinusX3_2 = x1Share2 - x3Share2 (mod P)
```

**✅ Local subtraction (no communication).**

### Substep 4b: Compute λ·(x1 - x3) (SECURE MULTIPLICATION)

Same process as Step 3a - uses another Beaver triple.

**📡 Communication:**
- Exchange ε and δ values
- Both reconstruct opened values
- Each completes multiplication locally

### Substep 4c: Compute y3 = result - y1

```go
y3Share1 = lambdaMultComplete1 - y1Share1 (mod P)
y3Share2 = lambdaMultComplete2 - y1Share2 (mod P)
```

**✅ Local subtraction (no communication).**

---

## Step 5: Opening the Final Result (Optional)

```go
x3, err := Open(x3Share1, x3Share2, peer1, peer2)
y3, err := Open(y3Share1, y3Share2, peer1, peer2)
```

**📡 Communication:**
- **Peer 1 sends**: `x3Share1`, `y3Share1` and their MACs
- **Peer 2 sends**: `x3Share2`, `y3Share2` and their MACs
- **Both compute**: `x3 = x3Share1 + x3Share2`, `y3 = y3Share1 + y3Share2`
- **Both verify**: MACs match expected values

**Result**: Both peers now know the final point `(x3, y3) = P1 + P2`

---

## Summary: What Gets Shared vs. Kept Private

### Shared/Communicated (Safe to reveal):
- ✅ Value shares (meaningless alone)
- ✅ MAC shares (meaningless alone)
- ✅ ε and δ from Beaver triple protocol (safe by design)
- ✅ Opened intermediate values like `x2-x1` (safe because it's a difference)
- ✅ Final result (if both parties agree to open)

### Never Shared (Kept Private):
- 🔒 Original input points: `pub1X, pub1Y, pub2X, pub2Y`
- 🔒 MAC key shares: `α₁`, `α₂`
- 🔒 Triple values: full `a, b, c` (only shares exchanged)
- 🔒 Intermediate computed values: `λ, λ², x3, y3` (only shares held until opened)

---

## Communication Rounds

The protocol requires approximately **5 rounds** of communication:

1. **Round 1-2**: Share initial points
   - Peer 1 → Peer 2: shares of `(pub1X, pub1Y)`
   - Peer 2 → Peer 1: shares of `(pub2X, pub2Y)`

2. **Round 3**: Open denominator for division
   - Both peers exchange denominator shares

3. **Round 4**: Open ε, δ for first multiplication (λ²)
   - Both peers exchange epsilon and delta values

4. **Round 5**: Open ε, δ for second multiplication (λ·(x1-x3))
   - Both peers exchange epsilon and delta values

5. **Round 6** (optional): Open final result
   - Both peers exchange final result shares

---

## Key Security Properties

### Input Privacy
Neither peer learns the other's input point throughout the computation.

### Computation Privacy
All intermediate values (λ, λ², etc.) remain secret-shared and are never revealed.

### Authenticity
MAC checks ensure no peer can tamper with shares without detection.

### Flexibility
Result can remain shared for further computation, or opened when both parties agree.

---

## Cost Analysis

### Computation (per peer):
- **Local operations**: ~20 additions, ~2 multiplications, ~10 modular reductions
- **Time**: Microseconds on modern CPUs

### Communication:
- **Data**: ~1-2 KB per round (256-bit field elements + MACs)
- **Rounds**: 5-6 rounds
- **Time**: Dominated by network latency (milliseconds to hundreds of milliseconds)

**Bottleneck**: Network communication, not computation!

---

## Conclusion

The SPDZ online phase demonstrates how two parties can jointly compute an elliptic curve point addition without revealing their private inputs. The protocol maintains security through:

1. **Additive secret sharing** - values split across parties
2. **Information-theoretic MACs** - detect any tampering
3. **Beaver triples** - enable secure multiplication
4. **Selective opening** - only reveal what's necessary

This makes SPDZ particularly well-suited for protocols requiring
multiple operations and conditional reveals, unlike garbled circuits
which require the full computation graph upfront.
