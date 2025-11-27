# SPDZ-MASCOT Protocol: Complete Breakdown from Each Peer's Perspective

## Phase 0: Setup - MAC Key Generation with OT

### Current Implementation

```go
func GenerateMACKeyWithOT() (*big.Int, *big.Int, error) {
    alpha1, _ := rand.Int(rand.Reader, P256Prime)
    alpha2, _ := rand.Int(rand.Reader, P256Prime)
    return alpha1, alpha2, nil
}
```

**⚠️ Note**: The current implementation is simplified. In production MASCOT, this uses a coin-tossing protocol with commitments to ensure neither party can bias the MAC key.

### How It Should Work (Production MASCOT)

#### Goal
Generate `α = α₁ + α₂ (mod P)` such that:
- Peer 1 knows only `α₁`
- Peer 2 knows only `α₂`
- Neither knows the full `α`
- Neither can bias the result

#### Protocol Steps

**Step 1: Commitment Phase**

```
Peer 1:
  1. Generate random α₁ ← Random(P256Prime)
  2. Compute commitment: C₁ = Hash(α₁ || r₁) where r₁ is random nonce
  3. Send C₁ to Peer 2

Peer 2:
  1. Generate random α₂ ← Random(P256Prime)
  2. Compute commitment: C₂ = Hash(α₂ || r₂) where r₂ is random nonce
  3. Send C₂ to Peer 1
```

**📡 Communication**: Each peer sends 32-byte commitment

**Step 2: Reveal Phase**

```
Peer 1:
  1. Send (α₁, r₁) to Peer 2

Peer 2:
  1. Send (α₂, r₂) to Peer 1
  2. Verify: C₁ = Hash(α₁ || r₁)
  3. If valid, accept α₁

Peer 1:
  1. Verify: C₂ = Hash(α₂ || r₂)
  2. If valid, accept α₂
```

**📡 Communication**: Each peer sends ~32 bytes (α value) + nonce

**Step 3: Local Computation**

```
Both peers compute (locally, no communication):
  α = α₁ + α₂ (mod P)
```

But each peer only stores their share:
- Peer 1 stores: `α₁`
- Peer 2 stores: `α₂`

### What Each Peer Knows After MAC Key Generation

| Peer 1 Knowledge | Peer 2 Knowledge | Neither Knows |
|------------------|------------------|---------------|
| `α₁` (private) | `α₂` (private) | Full `α` |
| `α₂` (received) | `α₁` (received) | |
| Can compute `α = α₁ + α₂` | Can compute `α = α₁ + α₂` | |

**🔑 Key Property**: While both peers *can* compute `α`, they only *store* their own share. This is safe because:
- MACs are verified using `α`, which both can compute
- But individual shares `α₁`, `α₂` remain secret to each peer
- An adversary compromising one peer doesn't learn `α` alone

### Security Analysis

#### Why Commitments?
Without commitments, a malicious peer could:
1. Wait to see the other peer's value
2. Choose their value to bias the result
3. Example: If Peer 2 wants `α = 0`, wait for `α₁`, then send `α₂ = -α₁`

With commitments:
- Must commit before seeing other's value
- Cannot change after seeing commitment
- Ensures randomness from both parties

#### Current Simplified Implementation
The current code skips commitments because:
- Simpler for demonstration
- Assumes semi-honest adversaries (follow protocol)
- In production, would need full commitment scheme

---

## Phase 1: OT Extension Setup

Before generating triples, peers set up OT extension infrastructure.

### Parameters

```go
params := &OTExtensionParams{
    SecurityParam: 128,  // κ = 128 base OTs
    NumOTs:        18,   // 3 triples × 6 OTs per triple
}
```

### Step 1: Base OTs (Roles Reversed!)

**Important**: In OT extension, roles are reversed for base OTs.

```go
SetupBaseOTs(peer1.OTSender, peer2.OTReceiver)
```

#### Peer 1 (Future OT Sender, Current OT Receiver):

```
1. Generate global correlation: Δ ← Random(128 bits)
2. For i = 0 to 127:
   - Extract bit: δᵢ = i-th bit of Δ
   - Prepare to receive: Will learn kᵢ^(δᵢ)
```

#### Peer 2 (Future OT Receiver, Current OT Sender):

```
1. For i = 0 to 127:
   - Generate two random seeds: k₀ᵢ, k₁ᵢ (16 bytes each)
   - Send both through base OT
   - Peer 1 receives: kᵢ^(δᵢ) based on their choice bit δᵢ
```

**📡 Communication**: 128 OTs × 2 seeds × 16 bytes = 4 KB (with optimizations)

**After base OTs:**
- **Peer 1 knows**: Δ (128-bit string), {kᵢ^(δᵢ)}ᵢ₌₀..₁₂₇
- **Peer 2 knows**: {(k₀ᵢ, k₁ᵢ)}ᵢ₌₀..₁₂₇

### Step 2: OT Extension (IKNP)

Now roles return to normal - Peer 1 as sender, Peer 2 as receiver.

#### Peer 2 (OT Receiver):

```go
U, err := peer2.OTReceiver.ExtendReceiver()
```

**Operations:**

```
1. Choose selection bits: r = (r₀, r₁, ..., r₁₇) - 18 random bits
2. For each OT j = 0 to 17:
   a. Compute row Tⱼ using PRG:
      Tⱼ[i] = PRG(kᵢ)[j] for i = 0..127

   b. Create matrix U to send:
      If rⱼ = 0: Uⱼ = Tⱼ
      If rⱼ = 1: Uⱼ = Tⱼ ⊕ s (where s is correlation string)

3. Send U matrix to Peer 1
```

**📡 Communication**: 18 rows × 16 bytes = 288 bytes

#### Peer 1 (OT Sender):

```go
err = peer1.OTSender.ExtendSender(U)
```

**Operations:**

```
1. Receive U matrix from Peer 2
2. For each OT j = 0 to 17:
   a. Compute Qⱼ using PRG:
      Qⱼ = PRG(k^δ)[j] for all base OTs

   b. Compute other matrix:
      Tⱼ = Qⱼ ⊕ Uⱼ

3. Store matrices Q and T
```

**After extension:**
- **Peer 1 has**: Matrices Q (for x₀ values) and T (for x₁ values)
- **Peer 2 has**: Matrix T and selection bits r
- **Property**: T corresponds to Peer 2's selected values

### Step 3: Bidirectional Setup

The same process is repeated in the opposite direction:

```go
SetupBaseOTs(peer2.OTSender, peer1.OTReceiver)
U, err := peer1.OTReceiver.ExtendReceiver()
err = peer2.OTSender.ExtendSender(U)
```

Now both peers can act as sender OR receiver as needed.

### Summary of OT Extension Setup

**Total Communication:**
- Base OTs (both directions): ~8 KB
- Extensions (both directions): ~576 bytes
- **Total**: ~9 KB

**Result:**
- 18 OTs ready in each direction
- Can generate 3 multiplication triples (6 OTs per triple)
- Amortized cost: ~500 bytes per triple

---

## Phase 2: MASCOT Offline Phase - Triple Generation with OT

### Goal
Generate multiplication triples `(a, b, c)` where `c = a × b (mod P)` such that:
- Peer 1 holds: `(a₁, b₁, c₁)` with MACs
- Peer 2 holds: `(a₂, b₂, c₂)` with MACs
- `a = a₁ + a₂`, `b = b₁ + b₂`, `c = c₁ + c₂`
- `c = a × b (mod P)`

### Triple Generation Process

```go
triple1, triple2, err := MASCOTTripleGenWithOT(peer1, peer2, tripleIndex)
```

#### Step 1: Generate Random Values (Centralized in Demo)

**⚠️ In production MASCOT**: This would use distributed generation, but for simplicity:

```
Generate (not by any peer, this is the "ideal" triple):
  a ← Random(P256Prime)
  b ← Random(P256Prime)
  c = a × b (mod P)
```

#### Step 2: Use OT to Distribute Shares

**Calculate OT indices for this triple:**
```
baseOTIdx = tripleIndex × 6
Use OTs: [baseOTIdx, baseOTIdx+1, ..., baseOTIdx+5]
```

**Peer 1 (OT Sender) prepares inputs:**

```
For each of 6 OTs needed:
  Generate random x₀ ← Random(256 bits)
  Compute x₁ = x₀ + Δ (mod P)  // Correlated using OT delta

Store:
  x₀[baseOTIdx] - will become a₁
  x₀[baseOTIdx+1] - will become b₁
  x₀[baseOTIdx+2] - will become c₁
  (and 3 more for MACs)
```

**Peer 1 encrypts and sends:**

```go
encX0, encX1, err := peer1.OTSender.DeriveOTs(x0Inputs, x1Inputs)
```

```
For each OT j:
  H₀ⱼ = Hash(Qⱼ || 0)
  H₁ⱼ = Hash(Tⱼ || 1)

  encX0[j] = x₀[j] ⊕ H₀ⱼ
  encX1[j] = x₁[j] ⊕ H₁ⱼ
```

**📡 Communication**: 18 encrypted values × 32 bytes = 576 bytes

**Peer 2 (OT Receiver) decrypts:**

```go
otOutputs, err := peer2.OTReceiver.ReceiveOTs(encX0, encX1)
```

```
For each OT j:
  H = Hash(Tⱼ || rⱼ)  // rⱼ is the selection bit

  If rⱼ = 0:
    output[j] = encX0[j] ⊕ H  // Recovers x₀
  If rⱼ = 1:
    output[j] = encX1[j] ⊕ H  // Recovers x₁ = x₀ + Δ
```

#### Step 3: Adjust Shares to Match Target Triple

**Peer 1:**
```
aShare1 = x₀[baseOTIdx] mod P
bShare1 = x₀[baseOTIdx+1] mod P
cShare1 = x₀[baseOTIdx+2] mod P
```

**Peer 2:**
```
aShare2 = a - aShare1 (mod P)
bShare2 = b - bShare1 (mod P)
cShare2 = c - cShare1 (mod P)
```

#### Step 4: Generate MACs

Both peers compute (using the shared knowledge of α = α₁ + α₂):

```
MAC(a) = α × a (mod P)
MAC(b) = α × b (mod P)
MAC(c) = α × c (mod P)
```

Then split each MAC additively:

```
Peer 1 gets: aMAC₁, bMAC₁, cMAC₁
Peer 2 gets: aMAC₂, bMAC₂, cMAC₂

Where: aMACᵢ + aMAC₂ = α × a (mod P)
```

**⚠️ Current implementation**: Uses simple additive sharing of MACs. Production MASCOT uses authenticated OT for this step.

#### Step 5: Store Triples

**Peer 1 stores:**
```go
triple1 := &Triple{
    A: &SPDZShare{Value: aShare1, MAC: aMAC1},
    B: &SPDZShare{Value: bShare1, MAC: bMAC1},
    C: &SPDZShare{Value: cShare1, MAC: cMAC1},
}
```

**Peer 2 stores:**
```go
triple2 := &Triple{
    A: &SPDZShare{Value: aShare2, MAC: aMAC2},
    B: &SPDZShare{Value: bShare2, MAC: bMAC2},
    C: &SPDZShare{Value: cShare2, MAC: cMAC2},
}
```

### Verification (In Production MASCOT)

After generating N triples, perform "cut-and-choose":

```
1. Randomly select N/2 triples to check
2. Both peers open these triples completely
3. Verify: c = a × b for each opened triple
4. If all checks pass, use remaining N/2 triples
5. If any check fails, abort (malicious behavior detected)
```

**Current implementation**: Skips cut-and-choose for simplicity.

### Summary of Triple Generation

**Per triple:**
- **Communication**: ~192 bytes (6 OTs × 32 bytes)
- **Computation**:
  - Peer 1: 6 PRG calls, 6 hashes, 3 additions
  - Peer 2: 6 PRG calls, 6 hashes, 6 additions
- **Result**: Both peers have authenticated shares of `(a, b, c)` where `c = a × b`

**For 3 triples:**
- **Total communication**: ~576 bytes
- **Time**: Milliseconds (dominated by network)

---

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

This makes SPDZ particularly well-suited for protocols requiring multiple operations and conditional reveals, unlike garbled circuits which require the full computation graph upfront.
