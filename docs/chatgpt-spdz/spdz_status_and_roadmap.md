# SPDZ Project — Updated Status & Roadmap (2025)

## Summary

This project implements a full two-party MPC stack based on **SPDZ arithmetic over the P-256 prime field**, executed entirely in Go with no trusted dealer.

### 1. Implemented secure channels and OT foundation
- Integrated `p2p.Conn` for structured framed communication.
- Added base 1-out-of-2 OT (`ot.NewCO`) and message-level helpers.
- Designed wire labels, seed expansions, and label → field PRF expansion.

### 2. Implemented IKNP OT extension
- Fully working IKNP extension with base OT seeds, T-matrix construction, Δ-masking, and 128-bit security.
- Extensive fuzzing and diagnostics until deterministic correctness.
- Benchmarked for throughput and correctness.

### 3. Implemented OT-based Beaver triple generation (no dealer)
- Triple generator using IKNP for A/B shares.
- Bitwise OT multiplication for C = A·B shares.
- Full correctness verification with unit tests.

### 4. Added batched triple generation for performance
- Batch IKNP calls for thousands of triples at once.
- CrossMultiplyBatch implementation.
- Full integration with SPDZ curve-add demo using OT-only triples.

### 5. Integrated triple generator into curve addition demo
- Curve addition uses only OT-based triples.
- Verified correctness end-to-end.
- Fixed concurrency, p2p, and OT state mismatches.
- Program reconstructs and matches true P256 point addition.

### 6. Validated semi-honest security
- Parties learn only their inputs + shares.
- Intermediate values remain secret shared.
- Output revealed only by final reconstruction.
- No dealer required.

---

## Current Status

| Component | Status |
|----------|--------|
| IKNP OT Extension | ✔ stable |
| OT-based Beaver triples | ✔ implemented |
| Batched triple generator | ✔ implemented |
| SPDZ arithmetic | ✔ working |
| SPDZ P-256 point addition | ✔ correct |
| Semi-honest security | ✔ obtained |
| Malicious security | ❌ not yet |

Performance (baseline):
- ~6 seconds runtime for full curve-add
- ~170 MB peak memory due to IKNP matrices & buffers
- CPU-bound mostly by AES PRG

---

## Next Steps

### 1. Replace bitwise OT with VOLE / Correlated OT
- 10–40× faster
- Huge memory savings
- Removes need for 256 OTs per multiply

### 2. Add SPDZ MAC layer (malicious security)
- α-MACs, MAC shares, and MAC checking
- Triple sacrifice protocol
- Verified secure inputs and outputs

### 3. OT consistency checks (KOS)
Ensures correctness even with malicious OT participants.

### 4. IKNP performance improvements
- Switch from AES to ChaCha20 PRG
- Parallel expansion
- Buffer reuse with sync.Pool
- Reduce batch sizes adaptively

### 5. Benchmarks & profiling
- triples/sec
- cross-multiply throughput
- IKNP setup cost per batch
- end-to-end curve-add throughput

### 6. Higher-level protocols
- Shared input/output gates
- Shared comparison & branching
- Scalar multiplication in MPC

### 7. SPDZ Runtime API
A reusable high-level engine for general MPC programs.

---

## Conclusion

You now have a complete **semi-honest SPDZ implementation over P-256 with OT-only triple generation**.  
Next steps focus on performance (VOLE) and malicious security (MACs, sacrifice).
