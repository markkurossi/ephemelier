# SPDZ Arithmetic Virtual Machine (AVM)

A modular, extensible **Arithmetic Virtual Machine (AVM)** for secure multiparty computation (MPC) over the P-256 prime field using SPDZ techniques.

The AVM transforms the SPDZ online protocol into a **clean, programmable execution engine** that runs arithmetic circuits consisting of:

- additions  
- multiplications (via Beaver triples)  
- subtractions  
- negation  
- exponentiation  
- inversion  
- opening/reconstruction  

The AVM abstracts triples, VOLE, OT extension, field operations, and networking—providing a **high-level programmable MPC backend**.

---

# 📐 Architecture Overview

GitHub renders **mermaid diagrams natively**, so the following visual architecture diagram is fully supported.

```mermaid
flowchart TD

    A[SPDZ VM<br/>Arithmetic Virtual Machine]:::blue

    subgraph Exec[Execution Layer]
        B[Instruction Processor]:::orange
        C[Program Memory]:::orange
    end

    subgraph Ops[Operation Layer]
        D[Arithmetic Primitives<br/>(Add, Mul, Sub, Inv, Exp)]:::green
        E[Preprocessing APIs<br/>(Beaver Triples, VOLE)]:::green
    end

    F[MPC Backend<br/>Network + Field Ops]:::lavender

    A --> Exec
    B --> D
    C --> D
    D --> F
    E --> F

classDef blue fill:#b3d9ff,stroke:#000,stroke-width:1px;
classDef orange fill:#ffd699,stroke:#000,stroke-width:1px;
classDef green fill:#c2f0c2,stroke:#000,stroke-width:1px;
classDef lavender fill:#e6ccff,stroke:#000,stroke-width:1px;
```

---

# 🎯 Goals

The AVM provides:

- A generic instruction set for MPC arithmetic  
- A register-based execution model  
- Pluggable triple sources (OT/IKNP, VOLE, Silent VOLE later)  
- Deterministic execution and easy testing  
- Structured basis for building compilers, DSLs, and optimizers  

It replaces ad-hoc procedural APIs with a structured **virtual machine model**.

---

# 🧩 Components

### **1. Registers**
Secret-shared values stored in VM-managed slots:

```go
type RegID int

type Register struct {
    Share Share // secret-shared field element
}
```

### **2. Instruction Set**

Minimal:

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

Optional extensions:

- `MULCONST`, `CMOV`, `ASSERT`
- `ECADD`, `ECMUL` (elliptic curve ops)
- `VECTOR-ADD/MUL` for SIMD

### **3. TripleSource**
A pluggable provider of Beaver triples:

```go
type TripleSource interface {
    NextTriple() (Share, Share, Share)
    NextBatch(n int) []Triple
}
```

Supports:
- VOLE triples  
- Deterministic test triples  
- Silent-VOLE later  

### **4. Executor**
Fetches instructions, performs SPDZ online protocol, updates registers.

```go
func (vm *AVM) Run(p Program) error
```

### **5. Backends**
- p2p.Conn  
- VOLE multiplication  
- OT extension  
- Field arithmetic (big.Int → limb arithmetic later)

---

# 🛠 Example: Building and Running a Program

```go
vm := avm.New(tripleSource, conn)

// Allocate registers
x := vm.InputReg()
y := vm.InputReg()
z := vm.Reg()
o := vm.OutputReg()

p := Program{}
p.AddConst(x, big.NewInt(5))
p.AddConst(y, big.NewInt(7))
p.Add(MUL, z, x, y)
p.Add(OPEN, o, z)

result := vm.Run(p)
```

Output:
```
5 * 7 = 35
```

All multiplications happen via SPDZ Beaver triples, hidden from the user.

---

# 🚀 Future Extensions

### Near-term
- α-MAC layer for malicious security  
- Triple sacrifice  
- Vectorization / SIMD registers  
- Parallel triple consumption  
- Multi-peer backends  

### Longer-term
- Silent VOLE integration  
- Circuit compiler DSL  
- Graph optimization passes  
- Mixed boolean/arithmetic circuits  
- GPU/AVX acceleration for limb arithmetic  

---

# 📦 Recommended Repository Layout

```
/avm
    vm.go
    program.go
    regs.go
    ops.go
    exec.go
    triples.go

/mpc
    share.go
    field.go
    mac.go

/vole
    vole.go
    packed.go

/ot
    base.go
    iknp.go

/examples
    curve_add/
    polynomial/
    vector_mul/

/docs
    spdz_vm_roadmap.md
    diagrams/
```

---

# 📄 License

MIT / Apache 2.0 — your choice.
