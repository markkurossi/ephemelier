# VOLE.go Code Review — Recommended Changes Summary

This document summarizes the major improvements, fixes, and cleanups suggested for `vole.go`.
These changes improve **security**, **performance**, **memory usage**, and **maintainability**.

---

# 1. Security Improvements

## 1.1 Replace Custom ChaCha20 Key Expansion with HKDF
Your current ChaCha20 PRG uses repeated key bytes, which is not secure.

**Fix:**
Use HKDF to derive a uniform key:
```go
key := hkdfExpand(label, "vole-chacha-prg", 32)
prgChaCha20Into(out, key)
```

---

## 1.2 Use HKDF for AES-CTR PRG Key Derivation
Labels from IKNP are not domain-separated cryptographic keys.

**Fix:**
```go
aesKey := hkdfExpand(label, "vole-aes-prg", 16)
prgAESInto(out, aesKey)
```

---

## 1.3 Document & Assert Nonce Reuse Assumption
Nonce = 0 is safe **only if each AES key is unique**.

**Fix:**
Add invariant comments and optional runtime check.

---

# 2. Performance Improvements

## 2.1 Remove BigInt Usage in VOLE Arithmetic
BigInt dominates your allocation and runtime cost.

**Fix:**
Define:
```go
type FE [32]byte
```

Implement:
- FEAdd
- FEMul
- FEReduce (Barrett/Montgomery)

Expected speedup: **3× to 5×**.

---

## 2.2 Avoid bytes32() Allocations
`bytes32(*big.Int)` allocates every time.

**Fix:**
Replace with:
```go
func writeBytes32(dst []byte, v *big.Int)
```
Preallocate all buffers.

---

## 2.3 Use bufPool Throughout Hot Paths
Currently only defined, not used.

Apply to:
- PRG pads
- y-vector
- u-vector
- temp 32-byte buffers

---

## 2.4 Preallocate y/u Output Buffers
Avoid append + reallocations.

**Fix:**
```go
outY := make([]byte, m*32)
for i := 0; i < m; i++ {
    writeBytes32(outY[i*32:], ui)
}
```

---

## 2.5 Avoid Recreating AES Cipher Per PRG Call
`aes.NewCipher(key)` allocates.

If reusable keys exist:
- Use a sync.Map or pool.
If not:
- Accept one allocation per key, eliminate all others.

---

# 3. Correctness & Maintainability Improvements

## 3.1 ExpandReceive Flags
You always pass `false` bits.

**Fix:**
- Document that otext ignores flags OR
- Pass real choice bits when available.

---

## 3.2 Document Receiver PRG Behavior
Receiver does **not** derive RS locally.

Add clarifying comment:
```go
// Receiver does not compute r_i; only Sender derives RS.
```

---

## 3.3 Clean up Redundant Code
- remove unused helpers
- collapse repeated code blocks
- clean up temporary slicing/padding logic

---

# 4. Summary of High-Impact Fixes

| Area | Impact | Recommendation |
|------|--------|----------------|
| Big.Int removal | ⭐⭐⭐⭐⭐ | Replace with fixed 32-byte FE |
| HKDF use | ⭐⭐⭐⭐ | Strengthens key separation |
| bufPool use | ⭐⭐⭐⭐ | Large GC reductions |
| bytes32 removal | ⭐⭐⭐⭐ | Removes thousands of allocs |
| AES cipher reuse | ⭐⭐⭐ | Minor improvement |
| Flag handling | ⭐⭐ | Correctness + clarity |

---

# 5. Expected Results After Fixes

- **Up to 5× faster VOLE** at large batch sizes
- **90–95% fewer allocations**
- **Lower GC pauses**
- **More secure PRG keying structure**
- **Cleaner, maintainable codebase**
