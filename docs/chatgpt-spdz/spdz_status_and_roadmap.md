# SPDZ Implementation — Status & Roadmap

_Last updated: 2025-11-28_

This document summarizes what we've implemented so far for the two-party SPDZ-based P-256 point-add MPC, what we discovered in debugging, and a prioritized, detailed list of remaining work (technical tasks, tests, and security considerations) so the project can be continued smoothly.

---

## 1. High-level overview

We built a two-party SPDZ-style online phase that computes the elliptic curve point addition P + Q over the P-256 field. The implementation currently runs with a *dealer-based* Beaver triple generator (peer 0 is dealer) and a correct online phase that uses those triples to perform secret-shared arithmetic, inversion (via exponentiation with `p-2`) and the elliptic addition formula in affine coordinates.

The implementation is in `spdz.go` (latest patched version). The main features:

- Field: prime field of elliptic.P256 (secp256r1 / P-256).
- Input sharing: owner masks input with random share and transmits the complement to the other peer (standard additive sharing).
- Beaver triple dealer: peer 0 samples global `a,b`, computes `c=a*b mod p`, then splits into additive shares `(a0,a1),(b0,b1),(c0,c1)`; peer 0 keeps its random shares and sends peer1's shares to peer1.
- MulShare: correct Beaver multiplication reassembling formula; only one party (id==0) adds the `d*e` public product to avoid doubling.
- Inversion: implemented by exponentiation `x^(p-2)` using square-and-multiply over secret-shared values (uses Beaver triples for each multiplication). `safeMul` wrapper ensures triple consumption is consistent.
- SPDZPointAdd: the full point-add sequence done inside MPC: compute `dx, dy` (shared), invert `dx` inside MPC, compute `lam`, `lam2`, `x3`, `y3` using shared operations.
- Tests & debugging: many debug runs were performed; we instrumented the exponentiation and multiplication to find a bug. We discovered that dealer triple packaging was wrong initially and fixed it; after that results matched the reference P+Q.


## 2. Files (current important artifacts)

- `spdz.go` — main implementation file (production build available). The most recent version contains:
  - Corrected Beaver triple dealer implementation.
  - Clean `MulShare`, `ExpShare`, `InvShare`, `SPDZPointAdd`, `ShareInput`, and `Peer` function.
  - A `debug` boolean toggle left in the file but all heavy debug code removed in the production build requested.

- `ctx-spdz.md`, `ctx-beaver-triple.md` — protocol/specification documents previously uploaded (used as spec/source for implementation). These remain important references.

- `main.go` (external, already present in repo) — test harness that creates the two peers, initializes inputs, and runs `Peer(...)` concurrently (not modified by me).

- Debug artifacts: previous debug-output blocks saved in conversation history — they show triple mismatches and step-by-step opened values. Keep them for audit.


## 3. What we have proven (test results)

- After fixing the triple packaging and the `MulShare` assembly, the reconstructed `Rx,Ry` matched the expected `P+Q` in the test harness for the sample inputs used during development.
- Extensive step-by-step opened logs show the MPC intermediate values after the fix; these confirm inversion and lam computations align with the reference.


## 4. Key design decisions & rationale

- **Dealer triples (temporary)**: Chosen for speed of prototyping — dealer (peer 0) generates triples and sends peer1 shares. This reduces complexity (no OT or network-heavy triple generation) and allows us to focus on online-phase correctness first.

- **Additive sharing, opening protocol ordering**: `openShare` and `openTwoShares` have asymmetric send/receive ordering to avoid deadlocks. This is preserved in production code.

- **d*e handling**: Only one party adds the `d*e` term to avoid double counting. This is important whenever both parties reconstruct partial terms.

- **Inversion via exponentiation**: Used Fermat's little theorem `x^(p-2)`. Implementation uses square-and-multiply consuming Beaver triples for each multiplication. This is simple and requires no additional protocols (but is heavy in triple usage).


## 5. Known limitations and assumptions

- **Offline phase is dealer-based**: Not secure for malicious settings nor ideal for unbiased adversary models. Dealer is trusted to produce correct triples.

- **Semi-honest compatibility**: Implementation assumes honest-but-curious peers; no MACs/authentication or cut-and-choose checks are present.

- **Triple budget**: Current triple budget is a rough upper bound (e.g., 1,200–1,600 triples in code). Precise triple count for inversion depends on exponent bit-length (≈511 multiplications for naive square-and-multiply of 256-bit exponent). Additional operations (lam, lam2, prod) consume more.

- **No active verification**: No checks (spot-check triples by revealing one party's shares or consistency checks). No zero-knowledge proofs.

- **Network layer**: relies on existing `p2p.Conn` semantics and `ot.OT` stubs in repo. The OT layer is not used yet for triple generation — it's reserved for OT-based protocol later.


## 6. Security considerations (short)

- Current dealer mode must be used **only** in a trusted-initializer setting (or test-only). For real-world deployment, replace dealer-mode with a cryptographically secure triple generation (e.g. OT-based, PRF-based, or honest majority) and/or add MACs on shares (SPDZ full protocol).

- Use authenticated shares (SPDZ MACs) if you need malicious-secure SPDZ. That requires a global MAC key share and MAC generation and checking.

- Be careful if enabling debug prints in live environments: debug reveals secret intermediate values and should only be used in development.


## 7. Remaining tasks (priority ordered)

Below is a comprehensive list of remaining work. Each item includes enough detail to begin coding and testing from the current repo state.

### High priority (must-do next)

1. **Replace dealer triples with OT‑based triple generation (secure, two‑party)**
   - Implement an OT-based offline phase so the triples are generated without a trusted dealer.
   - Options to consider:
     - **IKNP OT extension**: Use base OTs plus IKNP extension to expand to many correlated OTs; then use OT to obliviously transfer PRF seeds to expand into triples.
     - **Beaver triple via random OT multiplication**: For two-party, there's a direct approach: use correlated randomness from OT to generate shares of `a,b` and interactive reconstruction to compute `c` shares.
     - **Seed-OT + PRG label-expansion**: Use a label-expansion PRF to produce many correlated values per OT call.
   - Deliverables:
     - `triplegen_ot.go` implementing triple generation using `ot.OT` interface present in repo.
     - Clear API: `GenerateBeaverTriplesOT(conn, oti, id, n) ([]*Triple, error)` replacing dealer call.
   - Tests: triple consistency check (reconstruct random subset of triples and verify `a*b == c`).

2. **Add MACs / authentication to shares for malicious security (SPDZ full)**
   - Add global MAC key sharing and generate MAC tags for all shared values (triples, inputs, outputs).
   - Implement MAC checking on reconstructed values.
   - This is a larger project but necessary for a robust SPDZ.

3. **Optimize inversion**
   - Replace naive exponentiation with a windowed exponentiation or alternative inversion protocol (e.g., use extended GCD or use randomized inversion with fewer triples). This reduces triple consumption drastically.

4. **Triple consumption accounting & reduction**
   - Precisely count how many triples each phase consumes.
   - Tune `triplesNeeded` to a minimal safe value or dynamically request more triples on demand.

### Medium priority

5. **Unit tests & CI**
   - Unit tests for: `MulShare` (consistency), `GenerateBeaverTriplesDealer` (consistency), `InvShare` (inversion correctness), `SPDZPointAdd` (end-to-end equality with `elliptic.P256().Add`).
   - Add CI workflow to run two-peer harness tests.

6. **Performance profiling**
   - Measure runtime breakdown: triple generation (OT vs dealer), online multiplications, exponentiation cost.
   - Monitor network bytes and round trips.

7. **Pluggable triple-generation backend**
   - Implement an interface and allow switching between `Dealer` and `OT` triple generation at runtime.

8. **Documentation & protocol spec updates**
   - Update the spec files (the uploaded `ctx-*.md`) to reflect the exact wire-format of triple generation and opens.
   - Write a compact developer guide: how to run tests, how to enable debug, how to add new circuits.

### Low priority / Nice-to-have

9. **Batch inversion and optimization**
   - If many inversions are needed, implement batch inversion to amortize cost.

10. **Add support for projective coordinates**
   - Doing EC ops in projective coordinates reduces inversions (faster online) but complicates share conversions.

11. **Better API ergonomics**
   - Expose an API layer so new circuits can be written using share-level operators easily (Add, Mul, Inv, Open).


## 8. Design notes for OT-based triple-generation

This is the most important next engineering task. Below is a suggested design and step-by-step approach.

### Goal
Produce `n` Beaver triples `(A_i,B_i,C_i)` in additive shares such that each party obtains `(A0_i,B0_i,C0_i)` and `(A1_i,B1_i,C1_i)` with `A0+ A1 = a`, `B0 + B1 = b`, `C0 + C1 = a*b`.

### Approaches (two-party)

**A — OT-based multiplication (classic):**
- Let party A choose random `a0,a1` pair implicitly using OT and party B choose `b0,b1`.
- Use many 1-out-of-2 OTs to compute correlated randomness such that final `c` shares are computed without revealing `a` or `b`.
- Most concrete construction:
  - Use Correlated OT (COT/ROT) or IKNP-based extension to get many correlated seeds efficiently.
  - Using the COT outputs, evaluate a PRF to get bitwise shares and then assemble multi-limb field elements.

**B — PRF/label-expansion approach (recommended for speed):**
- Use OT or DH to exchange short seeds for each triple.
- Expand seeds locally using a cryptographic PRF (e.g., HMAC- or AES-CTR-based) to generate the many pseudorandom limbs needed for `a,b` and one-time MAC key material.
- Compute `c = a*b` locally in clear for the dealer; instead the party pairs exchange masked values via OT to let other party compute complementary shares.

**C — Use existing building block (if available):**
- If the repo already provides IKNP OT or a COT interface (check `ot.OT`), use that to implement `triplegen_ot.go`.

### Step-by-step (minimal working): OT-based Beaver triple generation

1. **Base OTs**: run base OTs to establish OT correlations (likely already in `ot.OT` library).
2. **Extend OTs** to get many COTs (IKNP or similar).
3. **For each triple**:
   - Use COT outputs to generate two random field elements `a`, `b` in additive shares.
   - Parties use OT to let one party send masked value of `a*b - c0` so the other gets their share `c1`. There are multiple specific protocols; pick a well-known construction (see literature: Beaver 1991, or more modern OT-based triple generation sketches by Gilboa, NDSS/Eurocrypt papers).
4. **Spot-checks**: verify correctness of a random subset of triples by opening them to ensure no misbehavior (only for testing/troubleshooting).

Deliverable: a tested `GenerateBeaverTriplesOT` function and tests that reconstruct random triples and verify `a*b==c`.


## 9. Testing plan (practical)

1. **Unit tests for primitives**
   - `TestMulShare` with small number of triples: reconstruct multiplication for random inputs.
   - `TestGenerateBeaverTriplesDealer` consistency checks.
   - `TestInvShareSmall` for random non-zero field elements.

2. **Integration tests**
   - Two-peer harness comparing `SPDZPointAdd` output with `elliptic.P256().Add` for many random P/Q.
   - Regression test that fails if any intermediate opened debug values differ from reference.

3. **OT-based triple generation tests**
   - Triple correctness for many triples (reconstruct random subset and verify `a*b == c`).
   - Edge cases: zero elements, maximal field values.

4. **Performance tests**
   - Measure triples/sec for dealer vs OT-based generation.
   - Measure end-to-end point-add latency.


## 10. Implementation checklist / suggested immediate tasks

1. Implement `triplegen_ot.go` with function `GenerateBeaverTriplesOT(conn, oti, id, n)`.
   - Use existing `ot.OT` interface; if narrow, add necessary OT primitives.
   - Create helpers to expand seeds to 256-bit field elements (32 bytes) properly reduced mod p.

2. Add unit tests for triple correctness and MulShare.

3. Replace `GenerateBeaverTriplesDealer` calls in `Peer` with a pluggable call that uses the OT variant when built with `--triplegen=ot` or using a runtime flag.

4. Implement small audit checks in debug builds: reconstruct and verify a small percentage (e.g., 1%) of triples at generation time.

5. Optimize `InvShare`: consider windowed exponentiation; measure triple consumption and adopt faster inversion if warranted.

6. Add optional MAC tags and tag-checking to move toward malicious security (this is larger and can be iterated).


## 11. Resource & timeline estimates (rough)

- **OT-based triple generator (prototype)**: 2–4 days of focused work (assuming `ot.OT` provides base OTs and IKNP extension). More if implementing OT extension from scratch.
- **Full test suite and CI integration**: 1–2 days.
- **Add MACs and malicious security**: multi-week effort depending on desired security model.


## 12. Appendices

### A — Triple count estimate
- Inversion via naive square-and-multiply over 256-bit exponent uses ≤ 511 multiplications (2*nbits - 1 worst-case with basic algorithm). Implementation uses 256 squarings + ~255 conditional multiplies.
- Additional multiplications for lam, lam2, prod and other operations add roughly ~10–20 multiplications per point-add.
- Conservative triple budget per point-add: 700–1400 triples depending on inversion implementation. After optimizing inversion, budget can drop well below 512.

### B — Debug logs
- Keep the debug outputs produced during development as forensic evidence of root cause and validation. They show the triple mismatch before fix and the matched intermediate values after the fix.

### C — Important code pointers
- `spdz.go` (latest production file) — main reference for sequence and share APIs.
- `main.go` — test harness to spin up two peers and exercise `Peer`.
- `ctx-spdz.md`, `ctx-beaver-triple.md` — original design spec and notes.

---

## Final notes

We now have a working *online* SPDZ point-add using dealer-generated triples. The next critical milestone is *replacing the dealer with OT-based triple generation* and adding verification (MACs) if the goal is to run in a non-trusted offline setting.

If you want I can:

- Produce `triplegen_ot.go` scaffolding and a minimal OT-based triple generator (prototype using existing `ot.OT`).
- Implement windowed exponentiation in `InvShare` (to reduce triple usage).
- Add the unit tests and CI workflow.

Which of these should I produce next?"

