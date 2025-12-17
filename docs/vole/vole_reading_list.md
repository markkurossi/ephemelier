# 📚 VOLE / OLE / PCG / MPC Reading List
A curated, practitioner‑oriented reading list covering the best and most useful academic papers and references for **Vector Oblivious Linear Evaluation (VOLE)**, **Oblivious Linear Evaluation (OLE)**, **PCGs**, and related **secure multi‑party computation** building blocks.

This list is organized in tiers:

1. Core VOLE papers
2. OLE (scalar) papers
3. PCG (Pseudorandom Correlation Generator) papers
4. OT Extension papers (foundational for OT‑based VOLE)
5. MPC preprocessing (Beaver / SPDZ / triples)
6. High‑level surveys & background

---

# 1. ⭐ Core VOLE Papers

## 1.1 Fast Vector Oblivious Linear Evaluation from Ring‑LWE
**J. Alamán de Castro, Y. V. Juvekar, T. Mayberry, D. Wichs, 2021**
Practical and efficient lattice‑based VOLE; strong post‑quantum security.
https://www.semanticscholar.org/paper/Fast-Vector-Oblivious-Linear-Evaluation-from-Ring-Castro-Juvekar/cb67a5faa5d2cee6fa01c6522e4189b7a172177b

## 1.2 Committed Vector Oblivious Linear Evaluation (C‑VOLE)
**J. Sun, Z. Liu, et al., 2025**
Introduces commitment-aware VOLE for verifiable preprocessing and consistency.
https://www.semanticscholar.org/paper/Committed-Vector-Oblivious-Linear-Evaluation-and-Sun-Liu/d26618fea0f1f7d860bdf33fd925466c23974780

## 1.3 Quantum Universally Composable Oblivious Linear Evaluation
**Santos, Mateus, Vlachou, 2022**
Analyzes OLE/VOLE security in Quantum‑UC framework.
https://quantum-journal.org/papers/q-2024-10-23-1507/pdf/

---

# 2. ⭐ OLE (Scalar) Papers

## 2.1 Efficient Protocols for OLE from Ring‑LWE
**Baum, Escudero, Pedrouzo‑Ulloa, Troncoso‑Pastoriza, 2021**
Key resource for scalar OLE; used widely in RLWE‑based MPC systems.
https://dl.acm.org/doi/10.1145/3474366.3486928

## 2.2 Secure Two‑Party Computation from OLE
**Ishai, Kushilevitz, Ostrovsky, Sahai (IKO), 2006**
First major formalization of OLE as a standalone primitive.

---

# 3. ⭐ PCG (Pseudorandom Correlation Generator) Papers
VOLE is foundational for PCGs used in fast preprocessing.

## 3.1 Pseudorandom Correlation Generators: Silent OT & Silent VOLE
**D. Wichs, P. Scholl, et al., 2019–2022**
Silent OT, silent VOLE, silent VSS — best introductions to amortized OT/VOLE.

## 3.2 Function Secret Sharing: Improvements and Applications
**Boyle, Gilboa & Ishai (2015‑2022)**
PCG-heavy constructions; essential background for VOLE-based MPC.

## 3.3 Fast Pseudorandom Correlation Generators for MPC
**Boyle, Kohlweiss, Scholl, et al., 2022**
General-purpose PCGs — VOLE and OT correlations at scale.

---

# 4. ⭐ OT Extension (Foundational for OT-based VOLE)

## 4.1 Extending Oblivious Transfers Efficiently
**Ishai, Kilian, Nissim, Petrank (IKNP), 2003**
The original OT-extension paper; base of all modern fast OT/VOLE.

## 4.2 More Efficient OT Extension (ALSZ)
**Asharov, Lindell, Schneider, Zohner, 2013/2015**
Industry‑standard optimized OT extension.
Provides malicious security.
*Best practical reference.*

## 4.3 Silent OT & Silent VOLE Techniques (Scholl, 2019+)
See PCG references above.

---

# 5. ⭐ MPC Preprocessing: Beaver, Triples & VOLE Integration

## 5.1 Multiparty Computation from Correlated Randomness
**Beaver, 1995**
Original Beaver triples paper. Still foundational.

## 5.2 SPDZ: Practically Efficient MPC
**Damgård, Pastro, Smart, Zakarias, CRYPTO 2012**
Uses OT/VOLE-like techniques and MAC checking.

## 5.3 High‑Throughput VOLE‑Based Triple Generation
(OPRF-like VOLE usage in modern MPC systems; various works by Wichs, Scholl, Boyle.)

---

# 6. ⭐ High-Level Surveys and Tutorials

## 6.1 Vector OLE & PCGs Overview (Slides, but excellent)
**Peter Scholl, NIST MPC Standards Workshop, 2023**
Great overview of VOLE, PCGs, correlations, silent VOLE.
https://csrc.nist.gov/csrc/media/Presentations/2023/mpts2023-day3-talk-gadgets-vole-pcg-cr/images-media/mpts2023-3a4-slides--scholl-vole-pcg-cr.pdf

## 6.2 Efficient Multi-Party Computation: A Survey
**Feng & Yang, 2022**
Cross-field overview of modern MPC systems and primitives.

## 6.3 Survey on OT Extension, Correlation Generators, OLE
(Academic compilations; varies by venue; generally secondary references.)

---

# 7. Recommended Reading Order (Practical)

If you're building **real systems**, this is the recommended reading sequence:

1. IKNP OT Extension (2003)
2. ALSZ OT Extension (2013/2015)
3. de Castro et al. "Fast VOLE from RLWE" (2021)
4. PCG papers (Silent OT/VOLE)
5. Committed VOLE (2025)
6. SPDZ / Beaver
7. Quantum OLE/VOLE (optional depth)

This gives you: practical → modern → scalable → secure → future-proof.

---

# 8. Appendix: VOLE Terminology Cheat Sheet

- **OLE (Oblivious Linear Evaluation)**
  Sender holds (a,b), receiver holds x → outputs ax + b mod p.

- **VOLE (Vector OLE)**
  Sender holds vector a, receiver holds vector x → outputs a·x + b.

- **Silent VOLE**
  Asymptotically silent generation of massive VOLE correlations.

- **C-VOLE**
  Committed VOLE (sender's vector bound to a commitment).

- **PCG**
  Pseudorandom Correlation Generator — produces many correlated values cheaply.

- **OT Extension**
  Extends few base OTs to many OTs efficiently; used to implement VOLE cheaply.
