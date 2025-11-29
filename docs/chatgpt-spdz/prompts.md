# SPDZ Support

You are an advanced Go programmer with security engineering
background. Analyze the attached protocol specification. Your task is
to implement the Peer function in the spdz.go file. Are the
instuctions complete? What additional infrastructure or library
functionality you would need?

# SPDZ Prompt Analysis

You are an LLM coding agent. Your task is to create program based on
the information in the attached contexts. Analyze the context
information from the implementation perspective. How could it be
improved? Is the overview clear enough?

# SPDZ Implementation

You are an advanced Go programmer with security engineering
background. Analyze the attached protocol specification. Your task is
to implement the Peer function in the spdz.go file. There exists a
`main.go` file with the `main` function. It creates the peers,
initializes their inputs, and runs the `Peer` function in
goroutines. Your task is to implement only the `Peer` function and any
support functions it needs.

# OT-based triple generation

Best match for this project (practical + secure): Start with IKNP OT
extension (Option 1) + PRG label-expansion (Option 3): IKNP for
inexpensive bulk OT, then expand OT seeds into many field elements
with a PRG/PRF. This is straightforward to implement on top of a basic
ot.OT interface, is widely used in practice, and gives a clear
migration path to higher-performance constructions (Silent OT / VOLE)
later.

Short plan (practical & safe):

1. Phase 0 — Prototype: Implement IKNP OT extension on top of your
   `ot.OT` interface. Use it to produce many basic Random OTs (ROT) or
   Correlated OTs (COT). Implement a simple PRG label expansion that
   maps each OT output to 32-byte field elements (reduce mod
   p). Generate `a,b` that way and compute `c = a*b mod p` locally in
   the dealer role of the triple generation protocol or via the
   symmetric protocol (see below). This gets you away from the trusted
   dealer and gives correct triples with modest engineering effort.

2. Phase 1 — Build triple generator (IKNP+PRG): Use the IKNP OTs as
   seeds; expand with PRG (e.g., AES-CTR or HKDF/HMAC-DRBG) into field
   elements. Implement `GenerateBeaverTriplesOT(conn, oti, id, n)`
   which produces additive shares for triples. Add a reconstruction
   spot-check mode (reveal a small random fraction of triples during
   debugging) to verify correctness while developing. This is robust
   and testable.
