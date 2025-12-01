# SPDZ Arithmetic VM Architecture & Development Roadmap

This document outlines how to refactor the current SPDZ implementation into a
clean, modular **Arithmetic Virtual Machine (AVM)** that executes circuits
consisting of generic operations (add, mult, sub, inv, exp, scalar mul, etc.)
over a secret-shared prime field.

The goal is to turn the existing ad‑hoc API into a reusable, efficient,
well‑structured backend that can support arbitrary MPC computations, optimizations,
and circuit compilers.

---

# 1. Motivation

Currently, SPDZ functionality is exposed via standalone functions such as:

- `AddShare(a, b)`
- `MulShare(triple, a, b)`
- `InvShare(a)`
- `ExpShare(a, k)`
- `SPDZPointAdd(P, Q)`
- Procedural triple generation
- Ad-hoc online protocol flows

This makes it difficult to:

- Reuse computation logic
- Build higher-level circuits
- Use uniform optimization passes
- Parallelize evaluation
- Support future features such as batch scheduling, SIMD, or lazy evaluation

A VM architecture provides a unified execution structure.

---

# 2. Goal: A Generic Arithmetic Virtual Machine (AVM)

The AVM is a component that:

- Accepts a list of *instructions*
- Stores secret-shared values in registers
- Fetches Beaver triples transparently
- Executes the SPDZ online protocol per instruction
- Produces output values for reconstruction
- Supports static or dynamic circuits

This allows:

- Circuit compilers → AVM bytecode  
- High-level MPC functions → AVM programs  
- Better testing, profiling, and debugging  
- Drop-in alternative backends (e.g., silent‑VOLE)  
- Consistent interface for research & production

---

# 3. AVM Core Concepts

## 3.1 Registers
A register holds a secret-shared value:

```
type RegID int

type Register struct {
    Share Share
}
```

Registers are allocated by the VM:
- Input registers
- Temporary registers
- Output registers

## 3.2 Instruction Set
Minimal core instruction set:

```
ADD   r_out, r_a, r_b
SUB   r_out, r_a, r_b
MUL   r_out, r_a, r_b
NEG   r_out, r_a
CONST r_out, c
INV   r_out, r_a
EXP   r_out, r_a, k
OPEN  r_out, r_a      ; reconstruction
```

Optional extended set:

```
MULCONST r_out, r_a, c
CMOV     r_out, r_cond, r_a, r_b
ASSERT   r_a
```

ECC-specific instructions (optional):

```
ECADD     r_out, P1_x, P1_y, P2_x, P2_y
ECMUL     r_out, P_x, P_y, scalar
```

## 3.3 VM State

```
type AVM struct {
    regs []Register
    triples TripleSource
    conn *p2p.Conn
    alphaMAC MACState    // optional, for malicious security
}
```

## 3.4 Program Representation

```
type Instruction struct {
    Op   Opcode
    Out  RegID
    In1  RegID
    In2  RegID
    Const *big.Int
}

type Program []Instruction
```

---

# 4. Development Steps

## Phase 1 — API Refactoring (Low-Risk, Structural)

1. **Create `avm/` package**
2. Define:
   - `Opcode` enum
   - `Instruction` struct
   - `Program` struct
   - `AVM` struct
3. Wrap existing SPDZ functions into VM operations:
   - `vm.executeAdd(a, b)`
   - `vm.executeMul(a, b)`
   - `vm.executeOpen(a)`
4. Register allocation helpers:
   - `vm.NewRegister()`
   - `vm.SetConst(reg, c)`
   - `vm.InputShare(reg, clear_value)`
5. Add `Run(program Program)` method.

Goal: *A minimal AVM that works with current SPDZ primitives.*

---

## Phase 2 — Triple Abstraction Layer

1. Define:

```
type TripleSource interface {
    NextTriple() (a, b, c Share)
    NextBatch(n int) []Triple
}
```

2. Replace direct triple generation calls with calls to the TripleSource:
   - Could wrap VOLE-based triple generator
   - Easy swap for:
     - benchmark triples
     - deterministic testing triples
     - silent‑VOLE triple factories

3. Allow prefetching & pipelining:
   - background goroutine fetching triples
   - VM consumes them on demand
   - reduces blocking I/O

---

## Phase 3 — Full Instruction Execution Engine

Implement a dispatch loop:

```
for pc := 0; pc < len(program); pc++ {
    switch inst.Op {
    case ADD:
        vm.add(inst.Out, inst.In1, inst.In2)
    case MUL:
        vm.mul(inst.Out, inst.In1, inst.In2)
    case INV:
        vm.inv(inst.Out, inst.In1)
    case OPEN:
        vm.open(inst.Out, inst.In1)
    ...
    }
}
```

Focus on correctness, deterministic execution, and clean separation from network code.

---

## Phase 4 — Public Interface Layer

Expose a simple API for constructing programs:

```
p := NewProgram()
x := p.Input()
y := p.Input()
z := p.Mul(x, y)
o := p.Output(z)
```

This layer mirrors typical arithmetic-circuit DSLs and enables:

- Compiler-friendly interface  
- Very compact MPC programs  
- Easier debugging  

Optional: add automatic register assignment & dead-register reuse.

---

## Phase 5 — Circuit Optimizations

Add optional offline passes:

### 5.1 Constant propagation
Replace expressions like:
```
a * 0 → 0
a * 1 → a
0 * b → 0
```

### 5.2 Operation fusion
Merge adjacent linear operations.

### 5.3 Topological scheduling
Reorder instructions to maximize:
- Triple prefetching
- Parallelism
- Cache locality

### 5.4 Batch optimization
If a program has many MULs:
- detect that they can be batched
- request VOLE/multiplication in bulk

---

# 6. Future Extensions

## 6.1 Gate-level circuits
Add boolean/arithmetic hybrid circuits.

## 6.2 SIMD & vectorization
Make registers store vectors:
```
[]Share
```

Execute Add/Mul elementwise → huge speedups.

## 6.3 Integration with compiler frontends
- DSL → AVM
- SQL / graph DSL → AVM
- ZK-friendly circuits (Plonk-like) → AVM

## 6.4 Malicious-security VM mode
- α-MAC tracking per register
- Assertions / range checks
- Sacrifice protocol integration
- Triple auditing

---

# 7. Deliverables Summary

### Deliverable 1 — `avm/` Package
- VM core + opcodes
- Program representation
- Register allocator
- Execution engine

### Deliverable 2 — TripleSource Abstraction
- Pluggable VOLE-based triple provider
- Support for queued / pipelined triple fetching

### Deliverable 3 — High-level API
- Functional builder for MPC programs
- Input/output management
- Full SPDZ compatibility

### Deliverable 4 — Optimizer Passes
- Optional optimization layers

### Deliverable 5 — Example VM Programs
- Point addition
- Matrix multiplication
- Polynomial evaluation

---

# 8. Recommended Development Sequence

1. **Create avm/ package & minimal VM**
2. **Migrate arithmetic ops to VM dispatch**
3. **Introduce TripleSource abstraction**
4. **Add high-level program builder API**
5. **Migrate curve-add demo to AVM**
6. **Add batch scheduling & pipelining**
7. **Add optimization passes**
8. **Add MACs & malicious-security support**
9. **Enable SIMD vector operations**
10. **Add compiler frontends**

---

# 9. Summary

This roadmap transitions your SPDZ codebase from:
- A collection of arithmetic helpers  
→ into  
- A full, reusable, optimizable MPC backend ("Arithmetic VM").

The AVM architecture makes it easy to:
- Build complex MPC applications
- Integrate silent VOLE
- Achieve malicious security
- Scale performance
- Add compiler/DSL frontends

It is the natural evolution of your current system.

