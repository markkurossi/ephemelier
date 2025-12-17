# SPDZ Implementation Roadmap

This roadmap summarizes the recommended next steps for stabilizing, optimizing, 
and extending the current SPDZ + VOLE implementation. It is organized in clear 
phases, with short actionable tasks.

---

# Phase 1 — Cleanup & Stability (Do First)

### 1. Remove / isolate legacy code
- Move `crossmul_bitwise.go` and `crossmul_bitwise_test.go` into a `legacy/` folder.
- Remove unused variables and leftover debug code.
- Move `main.go` into `examples/`.

### 2. Unify common constants and helpers
- Create a single `field/p256.go` file with:
  ```
  var P256 = elliptic.P256().Params().P
  ```
- Ensure all SPDZ and VOLE code consistently use this single field modulus.
- Consolidate duplicate `modReduce` helpers.

### 3. Strengthen correctness tests
Add:
- End-to-end test: share → add/mul → open → compare with plaintext.
- Large triple-batch test (e.g. 8192 triples).
- Deterministic tests for CrossMultiplyBatch.
- Randomized property tests for u - r = x*y (mod p) under VOLE.

---

# Phase 2 — Performance Improvements

### 1. Add sync.Pool resources
- Pool PRG buffers (ChaCha20 expansion).
- Pool big.Int scratch values.
- Pool p2p.Conn send/receive buffers.
- Pool temporary slices for VOLE batch scratch.

### 2. Parallelize PRG expansion
- Add goroutine worker pool for label expansions inside MulSender/MulReceiver.
- Benchmark 2-core / 4-core speedups.

### 3. Reduce allocations in VOLE
- Replace repeated `make([]byte, …)` with pooled buffers.
- Reuse per-batch VOLE scratch structures.

### 4. Tune batch size
- Benchmark GenerateBeaverTriplesOTBatch for: 512, 1024, 2048, 4096.
- Choose optimal batch size for your CPU.

---

# Phase 3 — SPDZ Security Layer (MACs & Checks)

### 1. Add α-MAC support
Each share becomes (value, mac = α·value):
- Implement ShareWithMAC.
- Add α distribution during setup.
- Modify triple generation to include MACs.

### 2. Implement Open + MAC check
- Add reconstruct-with-verification method.
- Abort if MAC mismatch.

### 3. Implement triple sacrifice
- Generate extra triples.
- Use half to check the other half.
- Abort on mismatch.

### 4. Implement triple auditing (optional)
- Sample triples.
- Reconstruct and verify correctness.

---

# Phase 4 — High-Performance Field Arithmetic

### 1. Replace big.Int with 256-bit limb arithmetic
Implement:
- FieldElem [4]uint64
- Montgomery multiplication
- Constant-time modular reduction

### 2. Convert all SPDZ and VOLE field operations
- Replace big.Int path with limb-based addition/multiplication.
- Add benchmarks comparing limb-based vs big.Int.

### 3. SIMD acceleration (optional)
- Evaluate AVX2/AVX-512 accelerated limb multiplication.

---

# Phase 5 — Silent VOLE (Optional, Advanced)

### 1. Re-introduce silent VOLE (Tiny-VOLE)
- Use GF(2) matrices + PRG-expanded Δ bits.
- Use deterministic matrix generator (H, G).
- Validate Lift(H⋅Δ) mapping experimentally.

### 2. Integrate into triple factory
- Replace packed-IKNP VOLE with silent VOLE for very large triple throughput.

---

# Phase 6 — Extended Documentation & Dev Experience

### 1. Write developer guide
- How input sharing works.
- How OT/VOLE are connected.
- How triples are generated.

### 2. Add profiling scripts
- CPU, alloc, and memory profiling for VOLE + triple generation.

### 3. Add examples directory
- Example SPDZ computation (e.g., point addition or polynomial evaluation).
- CLI tool demonstrating multiplication via triples.

---

# Summary

The SPDZ implementation is currently **correct and stable in the semi-honest model**. 
The highest-impact next steps are:

1. Cleanup (remove legacy OT-multiply code)
2. Add sync.Pool → huge performance win
3. Add MACs for full SPDZ security
4. Replace big.Int with limb arithmetic for 10–20× speedup

Silent VOLE and advanced optimizations can then be introduced cleanly.

