//

// Now you have a working (educational) implementation of SPDZ-MASCOT
// for secure 2-party elliptic curve point addition over P256. The
// implementation demonstrates:
//
// - MASCOT offline phase - generating authenticated multiplication triples
// - SPDZ online phase - secure computation with MAC authentication
// - Beaver multiplication - using triples for secure multiplication
// - EC point addition - computing the full point addition formula securely
// - MAC verification - detecting any tampering during computation
//
// For production use, you'd still want to consider:
//
// - Using MP-SPDZ (C++/Python) for performance and battle-tested security
// - Implementing proper oblivious transfer for the offline phase
// - Adding commitment schemes and zero-knowledge proofs
// - Optimizing finite field arithmetic
// - Handling edge cases (point doubling, point at infinity, etc.)

package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// P256Prime for field operations: (p = 2^256 - 2^224 + 2^192 + 2^96 - 1)
var P256Prime = elliptic.P256().Params().P

// SPDZShare represents a share in the SPDZ protocol: ⟨x⟩ = x_i + MAC_i
type SPDZShare struct {
	Value *big.Int // The additive share
	MAC   *big.Int // The MAC share
}

// Triple represents a Beaver multiplication triple (a, b, c) where c = a * b
type Triple struct {
	A *SPDZShare
	B *SPDZShare
	C *SPDZShare
}

// Peer represents a party in the SPDZ protocol
type Peer struct {
	ID         int
	Curve      elliptic.Curve
	MACKey     *big.Int     // α_i - share of global MAC key α
	Triples    []*Triple    // Preprocessed multiplication triples
	TripleIdx  int          // Current triple index
	RandomBits []*SPDZShare // Preprocessed random bits
	RandomIdx  int          // Current random bit index
}

// NewPeer creates a new peer
func NewPeer(id int, macKeyShare *big.Int) *Peer {
	return &Peer{
		ID:         id,
		Curve:      elliptic.P256(),
		MACKey:     macKeyShare,
		Triples:    make([]*Triple, 0),
		TripleIdx:  0,
		RandomBits: make([]*SPDZShare, 0),
		RandomIdx:  0,
	}
}

// ========== MASCOT Offline Phase ==========

// GenerateMACKey generates shares of the global MAC key using a
// simple 2-party protocol.
func GenerateMACKey() (*big.Int, *big.Int) {
	// α = α_1 + α_2 (mod p)
	alpha1, _ := rand.Int(rand.Reader, P256Prime)
	alpha2, _ := rand.Int(rand.Reader, P256Prime)
	return alpha1, alpha2
}

// MASCOTTripleGen generates a multiplication triple using MASCOT
// (simplified OT-based approach).
func MASCOTTripleGen(peer1, peer2 *Peer) (*Triple, *Triple) {
	// In real MASCOT, this uses oblivious transfer (OT) and
	// homomorphic commitments This is a simplified simulation for
	// demonstration.

	// Generate random a and b
	a, _ := rand.Int(rand.Reader, P256Prime)
	b, _ := rand.Int(rand.Reader, P256Prime)

	// Compute c = a * b (mod p)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, P256Prime)

	// Share a, b, c between the two peers
	aShare1, aShare2 := generateAdditiveShares(a, P256Prime)
	bShare1, bShare2 := generateAdditiveShares(b, P256Prime)
	cShare1, cShare2 := generateAdditiveShares(c, P256Prime)

	// Generate MACs for each share
	// Global MAC key
	alpha := new(big.Int).Add(peer1.MACKey, peer2.MACKey)
	alpha.Mod(alpha, P256Prime)

	// For each value x, we have: MAC(x) = α * x
	// This is split as: MAC_1(x) + MAC_2(x) = α * x
	// We need to distribute MAC shares properly

	aMACTotal := new(big.Int).Mul(alpha, a)
	aMACTotal.Mod(aMACTotal, P256Prime)
	aMAC1, aMAC2 := generateAdditiveShares(aMACTotal, P256Prime)

	bMACTotal := new(big.Int).Mul(alpha, b)
	bMACTotal.Mod(bMACTotal, P256Prime)
	bMAC1, bMAC2 := generateAdditiveShares(bMACTotal, P256Prime)

	cMACTotal := new(big.Int).Mul(alpha, c)
	cMACTotal.Mod(cMACTotal, P256Prime)
	cMAC1, cMAC2 := generateAdditiveShares(cMACTotal, P256Prime)

	triple1 := &Triple{
		A: &SPDZShare{Value: aShare1, MAC: aMAC1},
		B: &SPDZShare{Value: bShare1, MAC: bMAC1},
		C: &SPDZShare{Value: cShare1, MAC: cMAC1},
	}

	triple2 := &Triple{
		A: &SPDZShare{Value: aShare2, MAC: aMAC2},
		B: &SPDZShare{Value: bShare2, MAC: bMAC2},
		C: &SPDZShare{Value: cShare2, MAC: cMAC2},
	}

	return triple1, triple2
}

// generateAdditiveShares creates two additive shares of a value
func generateAdditiveShares(value, modulus *big.Int) (*big.Int, *big.Int) {
	share1, _ := rand.Int(rand.Reader, modulus)
	share2 := new(big.Int).Sub(value, share1)
	share2.Mod(share2, modulus)
	return share1, share2
}

// computeMAC computes MAC share for a value
func computeMAC(value, globalAlpha, localAlphaShare, modulus *big.Int) *big.Int {
	// For share value_i, the MAC share is: MAC_i = α * value (full
	// value, not just share)
	//
	// But we need to distribute this, so: MAC_i = α_i * value
	//
	// However, the correct way is: MAC = α * value, split as MAC_1 +
	// MAC_2 = α * value Where α = α_1 + α_2 So MAC_i is a random
	// share such that MAC_1 + MAC_2 = α * value
	mac := new(big.Int).Mul(globalAlpha, value)
	mac.Mod(mac, modulus)
	return mac
}

// ========== SPDZ Online Phase ==========

// SecretShare creates SPDZ shares of a value
func (p *Peer) SecretShare(value *big.Int, otherPeer *Peer) (
	*SPDZShare, *SPDZShare) {

	share1, share2 := generateAdditiveShares(value, P256Prime)

	// Global MAC key
	alpha := new(big.Int).Add(p.MACKey, otherPeer.MACKey)
	alpha.Mod(alpha, P256Prime)

	// MAC(value) = α * value, split into two shares
	macTotal := new(big.Int).Mul(alpha, value)
	macTotal.Mod(macTotal, P256Prime)
	mac1, mac2 := generateAdditiveShares(macTotal, P256Prime)

	s1 := &SPDZShare{
		Value: share1,
		MAC:   mac1,
	}

	s2 := &SPDZShare{
		Value: share2,
		MAC:   mac2,
	}

	return s1, s2
}

// Add performs addition of two SPDZ shares locally.
func (p *Peer) Add(a, b *SPDZShare) *SPDZShare {
	value := new(big.Int).Add(a.Value, b.Value)
	value.Mod(value, P256Prime)

	mac := new(big.Int).Add(a.MAC, b.MAC)
	mac.Mod(mac, P256Prime)

	return &SPDZShare{Value: value, MAC: mac}
}

// AddConstant adds a public constant to a share
func (p *Peer) AddConstant(share *SPDZShare, constant *big.Int) *SPDZShare {
	// Only peer 1 adds the constant to their share
	value := new(big.Int).Set(share.Value)
	if p.ID == 1 {
		value.Add(value, constant)
		value.Mod(value, P256Prime)
	}

	// MAC is updated by both parties: MAC'_i = MAC_i + α_i * c
	mac := new(big.Int).Set(share.MAC)
	macAdd := new(big.Int).Mul(p.MACKey, constant)
	macAdd.Mod(macAdd, P256Prime)
	mac.Add(mac, macAdd)
	mac.Mod(mac, P256Prime)

	return &SPDZShare{Value: value, MAC: mac}
}

// MultiplyConstant multiplies a share by a public constant
func (p *Peer) MultiplyConstant(share *SPDZShare, constant *big.Int) *SPDZShare {
	value := new(big.Int).Mul(share.Value, constant)
	value.Mod(value, P256Prime)

	mac := new(big.Int).Mul(share.MAC, constant)
	mac.Mod(mac, P256Prime)

	return &SPDZShare{Value: value, MAC: mac}
}

// Multiply performs secure multiplication using a Beaver triple
func (p *Peer) Multiply(x, y *SPDZShare) (map[string]*big.Int, int) {
	// Get next available triple
	if p.TripleIdx >= len(p.Triples) {
		panic("Not enough multiplication triples")
	}
	tripleIdx := p.TripleIdx
	triple := p.Triples[tripleIdx]
	p.TripleIdx++

	// Compute ε = x - a and δ = y - b
	epsilon := &SPDZShare{
		Value: new(big.Int).Sub(x.Value, triple.A.Value),
		MAC:   new(big.Int).Sub(x.MAC, triple.A.MAC),
	}
	epsilon.Value.Mod(epsilon.Value, P256Prime)
	epsilon.MAC.Mod(epsilon.MAC, P256Prime)

	delta := &SPDZShare{
		Value: new(big.Int).Sub(y.Value, triple.B.Value),
		MAC:   new(big.Int).Sub(y.MAC, triple.B.MAC),
	}
	delta.Value.Mod(delta.Value, P256Prime)
	delta.MAC.Mod(delta.MAC, P256Prime)

	// Return shares to be opened and the triple index
	return map[string]*big.Int{
		"epsilon": epsilon.Value,
		"delta":   delta.Value,
	}, tripleIdx
}

// CompleteMult completes the multiplication after opening ε and δ
func (p *Peer) CompleteMult(tripleIdx int, epsilonOpen, deltaOpen *big.Int) *SPDZShare {
	// z = c + ε*b + δ*a + ε*δ (for peer 1 only adds ε*δ to value)
	// The formula is: z = x*y = (a+ε)(b+δ) = ab + ε*b + δ*a + ε*δ
	// Since c = ab, we have: z = c + ε*b + δ*a + ε*δ

	triple := p.Triples[tripleIdx]

	// Value computation
	// ε * b_i (each peer multiplies by their share of b)
	term1 := new(big.Int).Mul(epsilonOpen, triple.B.Value)
	term1.Mod(term1, P256Prime)

	// δ * a_i (each peer multiplies by their share of a)
	term2 := new(big.Int).Mul(deltaOpen, triple.A.Value)
	term2.Mod(term2, P256Prime)

	// Start with c_i
	result := new(big.Int).Set(triple.C.Value)
	result.Add(result, term1)
	result.Add(result, term2)

	// Only peer 1 adds the public ε * δ term to the value
	if p.ID == 1 {
		term3 := new(big.Int).Mul(epsilonOpen, deltaOpen)
		term3.Mod(term3, P256Prime)
		result.Add(result, term3)
	}
	result.Mod(result, P256Prime)

	// MAC computation
	// MAC[z] = MAC[c] + ε*MAC[b] + δ*MAC[a] + α_i*ε*δ
	// Each peer adds their MAC shares and their share of the MAC for ε*δ

	macTerm1 := new(big.Int).Mul(epsilonOpen, triple.B.MAC)
	macTerm1.Mod(macTerm1, P256Prime)

	macTerm2 := new(big.Int).Mul(deltaOpen, triple.A.MAC)
	macTerm2.Mod(macTerm2, P256Prime)

	resultMAC := new(big.Int).Set(triple.C.MAC)
	resultMAC.Add(resultMAC, macTerm1)
	resultMAC.Add(resultMAC, macTerm2)

	// Each peer adds their share of α * (ε*δ)
	epsDelProduct := new(big.Int).Mul(epsilonOpen, deltaOpen)
	epsDelProduct.Mod(epsDelProduct, P256Prime)
	macTerm3 := new(big.Int).Mul(p.MACKey, epsDelProduct)
	macTerm3.Mod(macTerm3, P256Prime)
	resultMAC.Add(resultMAC, macTerm3)
	resultMAC.Mod(resultMAC, P256Prime)

	return &SPDZShare{Value: result, MAC: resultMAC}
}

// Open reveals a shared value with MAC check
func Open(share1, share2 *SPDZShare, peer1, peer2 *Peer) (*big.Int, error) {
	// Reconstruct value
	value := new(big.Int).Add(share1.Value, share2.Value)
	value.Mod(value, P256Prime)

	// Reconstruct MAC
	mac := new(big.Int).Add(share1.MAC, share2.MAC)
	mac.Mod(mac, P256Prime)

	// Verify: MAC = α * value
	alpha := new(big.Int).Add(peer1.MACKey, peer2.MACKey)
	alpha.Mod(alpha, P256Prime)

	expectedMAC := new(big.Int).Mul(alpha, value)
	expectedMAC.Mod(expectedMAC, P256Prime)

	if mac.Cmp(expectedMAC) != 0 {
		return nil, fmt.Errorf("MAC check failed")
	}

	return value, nil
}

// ========== Elliptic Curve Operations ==========

// ECPointAddition performs secure point addition P + Q using SPDZ
// Formulas for point addition (x3, y3) = (x1, y1) + (x2, y2):
// λ = (y2 - y1) / (x2 - x1)
// x3 = λ² - x1 - x2
// y3 = λ(x1 - x3) - y1
func ECPointAddition(x1Share1, y1Share1, x2Share1, y2Share1 *SPDZShare,
	x1Share2, y1Share2, x2Share2, y2Share2 *SPDZShare,
	peer1, peer2 *Peer) (*SPDZShare, *SPDZShare, *SPDZShare, *SPDZShare, error) {

	fmt.Println("\n--- Computing λ = (y2 - y1) / (x2 - x1) ---")

	// Compute numerator: y2 - y1
	negY1Share1 := &SPDZShare{
		Value: new(big.Int).Neg(y1Share1.Value),
		MAC:   new(big.Int).Neg(y1Share1.MAC),
	}
	negY1Share1.Value.Mod(negY1Share1.Value, P256Prime)
	negY1Share1.MAC.Mod(negY1Share1.MAC, P256Prime)

	negY1Share2 := &SPDZShare{
		Value: new(big.Int).Neg(y1Share2.Value),
		MAC:   new(big.Int).Neg(y1Share2.MAC),
	}
	negY1Share2.Value.Mod(negY1Share2.Value, P256Prime)
	negY1Share2.MAC.Mod(negY1Share2.MAC, P256Prime)

	numerator1 := peer1.Add(y2Share1, negY1Share1)
	numerator2 := peer2.Add(y2Share2, negY1Share2)

	// Compute denominator: x2 - x1
	negX1Share1 := &SPDZShare{
		Value: new(big.Int).Neg(x1Share1.Value),
		MAC:   new(big.Int).Neg(x1Share1.MAC),
	}
	negX1Share1.Value.Mod(negX1Share1.Value, P256Prime)
	negX1Share1.MAC.Mod(negX1Share1.MAC, P256Prime)

	negX1Share2 := &SPDZShare{
		Value: new(big.Int).Neg(x1Share2.Value),
		MAC:   new(big.Int).Neg(x1Share2.MAC),
	}
	negX1Share2.Value.Mod(negX1Share2.Value, P256Prime)
	negX1Share2.MAC.Mod(negX1Share2.MAC, P256Prime)

	denominator1 := peer1.Add(x2Share1, negX1Share1)
	denominator2 := peer2.Add(x2Share2, negX1Share2)

	// Open denominator to compute inverse (cannot do inversion on shares)
	denomOpen, err := Open(denominator1, denominator2, peer1, peer2)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Compute modular inverse
	denomInv := new(big.Int).ModInverse(denomOpen, P256Prime)
	if denomInv == nil {
		return nil, nil, nil, nil, fmt.Errorf("points are identical or inverse")
	}

	// λ = numerator * denomInv
	lambda1 := peer1.MultiplyConstant(numerator1, denomInv)
	lambda2 := peer2.MultiplyConstant(numerator2, denomInv)

	fmt.Println("--- Computing x3 = λ² - x1 - x2 ---")

	// λ²
	toOpen1, tripleIdx1 := peer1.Multiply(lambda1, lambda1)
	toOpen2, _ := peer2.Multiply(lambda2, lambda2)

	// Open ε and δ
	epsilonOpen := new(big.Int).Add(toOpen1["epsilon"], toOpen2["epsilon"])
	epsilonOpen.Mod(epsilonOpen, P256Prime)
	deltaOpen := new(big.Int).Add(toOpen1["delta"], toOpen2["delta"])
	deltaOpen.Mod(deltaOpen, P256Prime)

	// Complete multiplication
	lambdaSqComplete1 := peer1.CompleteMult(tripleIdx1, epsilonOpen, deltaOpen)
	lambdaSqComplete2 := peer2.CompleteMult(tripleIdx1, epsilonOpen, deltaOpen)

	// x3 = λ² - x1 - x2
	x3Share1 := peer1.Add(lambdaSqComplete1, negX1Share1)

	negX2Share1 := &SPDZShare{
		Value: new(big.Int).Neg(x2Share1.Value),
		MAC:   new(big.Int).Neg(x2Share1.MAC),
	}
	negX2Share1.Value.Mod(negX2Share1.Value, P256Prime)
	negX2Share1.MAC.Mod(negX2Share1.MAC, P256Prime)

	x3Share1 = peer1.Add(x3Share1, negX2Share1)

	x3Share2 := peer2.Add(lambdaSqComplete2, negX1Share2)

	negX2Share2 := &SPDZShare{
		Value: new(big.Int).Neg(x2Share2.Value),
		MAC:   new(big.Int).Neg(x2Share2.MAC),
	}
	negX2Share2.Value.Mod(negX2Share2.Value, P256Prime)
	negX2Share2.MAC.Mod(negX2Share2.MAC, P256Prime)

	x3Share2 = peer2.Add(x3Share2, negX2Share2)

	fmt.Println("--- Computing y3 = λ(x1 - x3) - y1 ---")

	// x1 - x3
	negX3Share1 := &SPDZShare{
		Value: new(big.Int).Neg(x3Share1.Value),
		MAC:   new(big.Int).Neg(x3Share1.MAC),
	}
	negX3Share1.Value.Mod(negX3Share1.Value, P256Prime)
	negX3Share1.MAC.Mod(negX3Share1.MAC, P256Prime)

	negX3Share2 := &SPDZShare{
		Value: new(big.Int).Neg(x3Share2.Value),
		MAC:   new(big.Int).Neg(x3Share2.MAC),
	}
	negX3Share2.Value.Mod(negX3Share2.Value, P256Prime)
	negX3Share2.MAC.Mod(negX3Share2.MAC, P256Prime)

	x1MinusX3_1 := peer1.Add(x1Share1, negX3Share1)
	x1MinusX3_2 := peer2.Add(x1Share2, negX3Share2)

	// λ * (x1 - x3)
	toOpen3, tripleIdx2 := peer1.Multiply(lambda1, x1MinusX3_1)
	toOpen4, _ := peer2.Multiply(lambda2, x1MinusX3_2)

	epsilon2 := new(big.Int).Add(toOpen3["epsilon"], toOpen4["epsilon"])
	epsilon2.Mod(epsilon2, P256Prime)
	delta2 := new(big.Int).Add(toOpen3["delta"], toOpen4["delta"])
	delta2.Mod(delta2, P256Prime)

	lambdaMultComplete1 := peer1.CompleteMult(tripleIdx2, epsilon2, delta2)
	lambdaMultComplete2 := peer2.CompleteMult(tripleIdx2, epsilon2, delta2)

	// y3 = λ(x1 - x3) - y1
	y3Share1 := peer1.Add(lambdaMultComplete1, negY1Share1)
	y3Share2 := peer2.Add(lambdaMultComplete2, negY1Share2)

	return x3Share1, y3Share1, x3Share2, y3Share2, nil
}

func main() {
	fmt.Println("=== SPDZ-MASCOT Protocol for Secure P256 Diffie-Hellman ===")
	fmt.Println()

	// ========== Setup Phase ==========
	fmt.Println("--- Setup Phase ---")

	// Generate MAC key shares
	alpha1, alpha2 := GenerateMACKey()
	fmt.Println("✓ Generated MAC key shares")

	// Create peers
	peer1 := NewPeer(1, alpha1)
	peer2 := NewPeer(2, alpha2)

	// ========== MASCOT Offline Phase ==========
	fmt.Println("\n--- MASCOT Offline Phase: Generating Multiplication Triples ---")

	// Generate triples for the multiplication operations needed
	// We need 3 multiplications per point addition: λ², λ*(x1-x3)
	numTriples := 3
	for i := 0; i < numTriples; i++ {
		triple1, triple2 := MASCOTTripleGen(peer1, peer2)
		peer1.Triples = append(peer1.Triples, triple1)
		peer2.Triples = append(peer2.Triples, triple2)
	}
	fmt.Printf("✓ Generated %d multiplication triples\n", numTriples)

	// ========== Diffie-Hellman Setup ==========
	fmt.Println("\n--- Creating sample points ---")

	curve := elliptic.P256()

	x1, ok := new(big.Int).SetString("bb32c4722cbd5a05510cfbb9c4c152f144e70fa24b9e428b9b3bf9f39dd43bbe", 16)
	y1, ok := new(big.Int).SetString("25b7f3d9d79e5ca057b0ba7a940d5c917d41cc0a08d41cb1b2b83905e795c7db", 16)
	x2, ok := new(big.Int).SetString("7aaf9286743dc0adbd8fa93d305521cf0f62947ee5831bc8e355b133de65bd5a", 16)
	y2, ok := new(big.Int).SetString("5e183e2d1f66256cc42883de880fdc7c177e99f2e003a2dd298e458aaebcc799", 16)
	_ = ok

	// ========== SPDZ Online Phase ==========
	fmt.Println("\n--- SPDZ Online Phase: Secure Point Addition ---")

	// Share peer 1's public key
	x1Share1, x1Share2 := peer1.SecretShare(x1, peer2)
	y1Share1, y1Share2 := peer1.SecretShare(y1, peer2)
	fmt.Println("✓ Peer 1's public key shared")

	// Share peer 2's public key
	x2Share1, x2Share2 := peer2.SecretShare(x2, peer1)
	y2Share1, y2Share2 := peer2.SecretShare(y2, peer1)
	fmt.Println("✓ Peer 2's public key shared")

	// Perform secure point addition: P1 + P2
	fmt.Println("\nPerforming secure elliptic curve point addition...")
	x3Share1, y3Share1, x3Share2, y3Share2, err := ECPointAddition(
		x1Share1, y1Share1, x2Share1, y2Share1,
		x1Share2, y1Share2, x2Share2, y2Share2,
		peer1, peer2,
	)

	if err != nil {
		fmt.Printf("Error during point addition: %v\n", err)
		return
	}

	fmt.Println("\n✓ Secure point addition completed")

	// ========== Verification ==========
	fmt.Println("\n--- Opening and Verifying Result ---")

	// Open the result
	x3, err := Open(x3Share1, x3Share2, peer1, peer2)
	if err != nil {
		fmt.Printf("Error opening x3: %v\n", err)
		return
	}

	y3, err := Open(y3Share1, y3Share2, peer1, peer2)
	if err != nil {
		fmt.Printf("Error opening y3: %v\n", err)
		return
	}

	fmt.Printf("\nResult point: P3 = P1 + P2\n")
	fmt.Printf("X: %s\n", x3.Text(16))
	fmt.Printf("Y: %s\n", y3.Text(16))

	// Verify against direct computation
	directX, directY := curve.Add(x1, y1, x2, y2)

	if x3.Cmp(directX) == 0 && y3.Cmp(directY) == 0 {
		fmt.Println("\n✓ SUCCESS: SPDZ result matches direct computation!")
	} else {
		fmt.Println("\n✗ FAILURE: Results do not match")
		fmt.Printf("Expected X: %s...\n", directX.String()[:50])
		fmt.Printf("Expected Y: %s...\n", directY.String()[:50])
	}

	// Verify point is on curve
	if curve.IsOnCurve(x3, y3) {
		fmt.Println("✓ Result is a valid point on P256 curve")
	} else {
		fmt.Println("✗ Result is NOT on P256 curve")
	}

	// Compute shared secret hash (for demonstration)
	sharedSecret := sha256.Sum256(append(x3.Bytes(), y3.Bytes()...))
	fmt.Printf("\nShared DH secret (SHA-256): %x...\n", sharedSecret[:16])

	fmt.Println("\n=== Protocol Complete ===")
}
