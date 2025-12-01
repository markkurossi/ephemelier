# SPDZ Arithmetic Virtual Machine (AVM) Architecture

This document provides a detailed technical overview of the AVM architecture
that complements the GitHub README. It explains the system components,
dataflow, abstractions, and extension points used to build a modular,
high‑performance SPDZ-based MPC backend.

---

# 1. Architectural Goals

The AVM provides:

- A unified execution engine for SPDZ arithmetic  
- A stable foundation for instruction-based MPC computation  
- Pluggable preprocessing backends (VOLE, OT, Silent VOLE)  
- Optimizable circuits via instruction scheduling  
- Clear separation of online protocol logic and preprocessing  
- Compatibility with future compiler and DSL toolchains  

It is the evolution from procedural SPDZ calls → a full virtual machine.

---

# 2. High-Level Overview

```
 +-----------------------+
 |      User Program     |
 |  (Circuit or Builder) |
 +-----------------------+
             |
             v
 +-----------------------+
 |        Program        |
 |   (Instructions IR)   |
 +-----------------------+
             |
             v
 +-----------------------+
 |         AVM           |
 |  - Registers          |
 |  - Execution Engine   |
 |  - TripleSource       |
 +-----------------------+
             |
             v
 +-----------------------+
 |   SPDZ Primitives     |
 |  Add / Mul / Inv etc. |
 +-----------------------+
             |
             v
 +-----------------------+
 |  VOLE / OT Extension  |
 |   Beaver Triple Gen   |
 +-----------------------+
             |
             v
 +-----------------------+
 |   p2p Conn Network    |
 +-----------------------+
```

The entire system is cleanly layered, making each part testable and independently evolvable.

---

# 3. Core Components

## 3.1 Registers

Registers hold secret-shared field elements:

```
type Register struct {
    Share Share
}
```

Registers behave like CPU registers:

- Allocated by the VM
- Referenced by RegID
- Reused by the optimizer
- Passed between instructions

---

## 3.2 Instructions

The VM supports a minimal but powerful instruction set:

```
ADD   r_out, r_a, r_b
SUB   r_out, r_a, r_b
MUL   r_out, r_a, r_b
NEG   r_out, r_a
INV   r_out, r_a
EXP   r_out, r_a, k
CONST r_out, c
OPEN  r_out, r_a
```

Each instruction represents a single MPC online protocol step.

---

## 3.3 TripleSource

An abstraction defining how triples are supplied:

```
type TripleSource interface {
    NextTriple() (a, b, c Share)
    NextBatch(n int) []Triple
}
```

Backends include:

- Packed VOLE-based triple source  
- Deterministic triple source (testing)  
- Silent-VOLE triple source (future)  

This separation decouples preprocessing from online protocol execution.

---

## 3.4 Execution Engine

The VM maintains:

- Register file
- Program counter (PC)
- TripleSource instance
- Network connection
- Field modulus (P-256)
- Optional MAC state (malicious-security mode)

Main loop:

```
for pc := 0; pc < len(program); pc++ {
    inst := program[pc]
    vm.execute(inst)
}
```

The execution engine handles:

- Online communication
- Triple consumption
- Field arithmetic
- Register updates
- Opening with MAC checking (future)

---

# 4. Dataflow in a Multiplication Instruction

Example: `MUL r3, r1, r2`

**Steps:**

1. VM requests triple `(a, b, c)` from TripleSource.
2. Computes local masked values:  
   `d = x - a`  
   `e = y - b`
3. Performs open protocol:  
   `d_open = Open(d)`  
   `e_open = Open(e)`
4. Computes shared result:  
   `z = c + e_open * a + d_open * b + d_open * e_open`

VM ensures:

- MAC consistency (future)
- Triple correctness (optionally checked)

---

# 5. Extension Layers

## 5.1 Malicious Security Upgrade

Add MAC tracking:

- Each register holds `(value, mac)`
- VM verifies all openings
- TripleSource produces `(a, b, c, macs)`
- Add triple sacrifice support

## 5.2 Vectorized Registers (SIMD)

Extend registers to hold slices:

```
type Register struct {
    Shares []Share
}
```

Enable:

- vector add/mul
- matrix operations
- batch-friendly VOLE

## 5.3 Gate-Level Hybrid Circuits

Add boolean gates with arithmetic–boolean conversion:

- AND/OR/XOR
- Bit decomposition
- Comparison circuits

## 5.4 Compilers & DSL Frontends

Input DSL → IR → AVM program:

- polynomial evaluation
- matrix multiplication
- EC operations
- SQL/MPC queries
- Graph analytics

---

# 6. Suggested Folder Structure

```
/avm
    vm.go
    program.go
    registers.go
    instructions.go
    executor.go
    triples.go
    optimizer.go   (future)

/vole
/ot
/mpc
/examples
/docs
```

---

# 7. Implementation Roadmap

## Phase 1 — Build AVM Skeleton
- Define opcodes and instruction structs
- Add register allocator
- Add Program type
- Implement minimal executor

## Phase 2 — Wrap Existing SPDZ Operations
- Redirect Add/Mul/Sub/Inv into AVM engine
- Provide Drop-in TripleSource backed by VOLE

## Phase 3 — High-Level API
- Builder for constructing circuits programmatically
- Input/output handling
- Automatic register reuse

## Phase 4 — Optimization Passes
- Constant folding
- Linear operation fusion
- Multiplication batching
- Topological scheduling

## Phase 5 — Malicious Security Layer
- Add α-MAC tracking
- Implement Open + MAC check
- Add triple sacrifice

## Phase 6 — Advanced Features
- SIMD registers
- Silent VOLE backend
- DSL compiler integration
- Boolean/arithmetic hybrid circuits

---

# 8. Summary

The AVM architecture transforms a procedural SPDZ implementation
into a general-purpose arithmetic execution engine suitable for:

- compiler frontends  
- batch MPC operations  
- SIMD acceleration  
- malicious-secure computation  
- large program evaluation  

It makes the system modular, scalable, and future‑proof.

