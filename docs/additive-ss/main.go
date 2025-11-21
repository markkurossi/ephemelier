package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

// P256 curve parameters.
var (
	curve  = elliptic.P256()
	curveN = curve.Params().N // curve order
)

// Point represents an elliptic curve point.
type Point struct {
	X, Y *big.Int
}

// ServerPeer represents a server peer with its share of the private
// key.
type ServerPeer struct {
	Name   string
	AlphaI *big.Int // Private key share: αᵢ
	PubKey *Point   // Public key share: αᵢ·G
}

// NewServerPeer creates a new server peer with a random key share.
func NewServerPeer(name string) (*ServerPeer, error) {
	// Sample αᵢ ← Z_p+
	alphaI, err := rand.Int(rand.Reader, curveN)
	if err != nil {
		return nil, fmt.Errorf("failed to generate alphaI for %s: %w",
			name, err)
	}

	// Compute αᵢ·G
	pubX, pubY := curve.ScalarBaseMult(alphaI.Bytes())

	return &ServerPeer{
		Name:   name,
		AlphaI: alphaI,
		PubKey: &Point{X: pubX, Y: pubY},
	}, nil
}

// ComputePartialDH computes αᵢ·(β·G) - the peer's contribution to the
// DH result.
func (p *ServerPeer) ComputePartialDH(serverPublicKey *Point) *Point {
	// Compute αᵢ·(β·G)
	partialX, partialY := curve.ScalarMult(serverPublicKey.X, serverPublicKey.Y,
		p.AlphaI.Bytes())

	return &Point{
		X: partialX,
		Y: partialY,
	}
}

// ServerSide represents the distributed TLS client (N servers acting
// as client).
type ServerSide struct {
	Name           string
	Peers          []*ServerPeer
	CombinedPubKey *Point // α·G = Σ(αᵢ·G)
}

// NewServerSide creates N servers that will act as a distributed TLS
// client.
func NewServerSide(name string, numPeers int) (*ServerSide, error) {
	peers := make([]*ServerPeer, numPeers)

	// Step 1.1: Each server Pᵢ samples αᵢ and computes αᵢ·G
	for i := 0; i < numPeers; i++ {
		peer, err := NewServerPeer(fmt.Sprintf("%s-Peer%d", name, i+1))
		if err != nil {
			return nil, err
		}
		peers[i] = peer
	}

	// Step 1.2: P1 (forwarding server) computes α·G = Σ(αᵢ·G)
	combinedX := big.NewInt(0)
	combinedY := big.NewInt(0)

	for _, peer := range peers {
		combinedX, combinedY = curve.Add(combinedX, combinedY,
			peer.PubKey.X, peer.PubKey.Y)
	}

	return &ServerSide{
		Name:  name,
		Peers: peers,
		CombinedPubKey: &Point{
			X: combinedX,
			Y: combinedY,
		},
	}, nil
}

// GetClientHelloPublicKey returns the combined public key α·G for
// ClientHello.
func (s *ServerSide) GetClientHelloPublicKey() *Point {
	return s.CombinedPubKey
}

// DeriveSharedSecret performs distributed computation of αβ·G
func (s *ServerSide) DeriveSharedSecret(tlsServerPublicKey *Point) (
	[]byte, error) {

	// Step 2: Each party Pᵢ computes αᵢ·(β·G)
	partialResults := make([]*Point, len(s.Peers))

	fmt.Println("\n  Partial DH Computations:")
	for i, peer := range s.Peers {
		partial := peer.ComputePartialDH(tlsServerPublicKey)
		partialResults[i] = partial
		fmt.Printf("  • %s computes αᵢ·(β·G): (%s..., %s...)\n",
			peer.Name,
			hex.EncodeToString(partial.X.Bytes())[:16],
			hex.EncodeToString(partial.Y.Bytes())[:16])
	}

	// SMPC engine computes αβ·G = Σ(αᵢ·(β·G))

	fmt.Println("\n  SMPC Engine Combining Results:")
	finalX := big.NewInt(0)
	finalY := big.NewInt(0)

	for i, partial := range partialResults {
		finalX, finalY = curveAdd(finalX, finalY, partial.X, partial.Y)
		fmt.Printf("  • Added contribution from Peer%d\n", i+1)
	}

	// Use X-coordinate as shared secret (standard ECDH practice)
	sharedSecret := finalX.Bytes()

	// Pad to 32 bytes if necessary
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	return sharedSecret, nil
}

// ClientSide represents the TLS server S
type ClientSide struct {
	Name      string
	Beta      *big.Int // Private key: β
	PublicKey *Point   // Public key: β·G
}

// NewClientSide creates a TLS server with standard ECDH
func NewClientSide(name string) (*ClientSide, error) {
	// Sample β ← Z_p+
	beta, err := rand.Int(rand.Reader, curveN)
	if err != nil {
		return nil, err
	}

	// Compute β·G
	pubX, pubY := curve.ScalarBaseMult(beta.Bytes())

	return &ClientSide{
		Name: name,
		Beta: beta,
		PublicKey: &Point{
			X: pubX,
			Y: pubY,
		},
	}, nil
}

// DeriveSharedSecret performs standard ECDH: β·(α·G)
func (c *ClientSide) DeriveSharedSecret(clientPublicKey *Point) (
	[]byte, error) {

	// Compute β·(α·G) = αβ·G
	sharedX, sharedY := curve.ScalarMult(clientPublicKey.X, clientPublicKey.Y,
		c.Beta.Bytes())
	_ = sharedY

	// Use X-coordinate as shared secret
	sharedSecret := sharedX.Bytes()

	// Pad to 32 bytes if necessary
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	return sharedSecret, nil
}

func main() {
	fmt.Println("SECP256R1 with Additive Secret Sharing (TLS 1.3 Style)")
	fmt.Println("======================================================")
	fmt.Println()

	fmt.Println("Protocol Overview:")
	fmt.Println("------------------")
	fmt.Println("N servers act as distributed TLS client P")
	fmt.Println("Client S is the TLS server")
	fmt.Println("Using additive secret sharing with SMPC")
	fmt.Println()

	// Create distributed TLS client (N servers)
	numServers := 2
	distributedClient, err := NewServerSide("DistributedClient", numServers)
	if err != nil {
		log.Fatal(err)
	}

	// Create TLS server
	tlsServer, err := NewClientSide("TLSServer")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== STEP 1: Distributed Generation of Key Share α·G ===")
	fmt.Println()

	fmt.Println("1.1) Each server Pᵢ samples αᵢ and computes αᵢ·G:")
	for i, peer := range distributedClient.Peers {
		fmt.Printf("  • %s: αᵢ=%s..., αᵢ·G=(%s..., %s...)\n",
			peer.Name,
			hex.EncodeToString(peer.AlphaI.Bytes())[:16],
			hex.EncodeToString(peer.PubKey.X.Bytes())[:16],
			hex.EncodeToString(peer.PubKey.Y.Bytes())[:16])

		if i < len(distributedClient.Peers)-1 {
			fmt.Printf("     Reveals αᵢ·G to other parties\n")
		}
	}

	fmt.Println("\n1.2) P1 (forwarding server) computes α·G = Σ(αᵢ·G):")
	fmt.Printf("  • Combined public key α·G:\n")
	fmt.Printf("    X: %s...\n",
		hex.EncodeToString(distributedClient.CombinedPubKey.X.Bytes())[:64])
	fmt.Printf("    Y: %s...\n",
		hex.EncodeToString(distributedClient.CombinedPubKey.Y.Bytes())[:64])

	fmt.Println("\n1.3) P1 sends ClientHello with α·G to TLS server")

	fmt.Println("\n=== STEP 2: TLS Server Response ===")
	fmt.Println()
	fmt.Printf("TLS Server generates β and sends ServerHello with β·G:\n")
	fmt.Printf("  • β·G:\n")
	fmt.Printf("    X: %s...\n",
		hex.EncodeToString(tlsServer.PublicKey.X.Bytes())[:64])
	fmt.Printf("    Y: %s...\n",
		hex.EncodeToString(tlsServer.PublicKey.Y.Bytes())[:64])

	fmt.Println("\n=== STEP 3: Distributed Computation of DH Key αβ·G ===")

	// Distributed client computes shared secret.
	clientSharedSecret, err := distributedClient.DeriveSharedSecret(
		tlsServer.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n  SMPC Result: αβ·G computed successfully")

	// TLS server computes shared secret
	fmt.Println("\n=== TLS Server Computation ===")
	fmt.Println()
	fmt.Println("TLS Server computes β·(α·G) = αβ·G:")
	serverSharedSecret, err := tlsServer.DeriveSharedSecret(
		distributedClient.CombinedPubKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n=== Results ===")
	fmt.Println()
	fmt.Println("Derived Secrets:")
	fmt.Println("----------------")
	fmt.Printf("Distributed Client's secret: %s\n",
		hex.EncodeToString(clientSharedSecret))
	fmt.Printf("TLS Server's secret        : %s\n\n",
		hex.EncodeToString(serverSharedSecret))

	// Verify
	fmt.Println("Verification:")
	fmt.Println("-------------")
	if hex.EncodeToString(clientSharedSecret) ==
		hex.EncodeToString(serverSharedSecret) {

		fmt.Println("✓ Success! Both sides derived the same shared secret αβ·G")
		fmt.Printf("Shared secret length: %d bytes\n\n",
			len(clientSharedSecret))

		fmt.Println("Key Properties of Additive Secret Sharing:")
		fmt.Println("-------------------------------------------")
		fmt.Println("• No master private key ever exists")
		fmt.Println("• Each server only knows their own αᵢ")
		fmt.Println("• α = Σαᵢ is never computed or stored anywhere")
		fmt.Println("• Simple addition for combining (no Lagrange needed)")
		fmt.Println("• TLS server sees only one client with public key α·G")
		fmt.Println("• More efficient than polynomial secret sharing")

		fmt.Println("\n=== STEP 4: Key Derivation (Conceptual) ===")
		fmt.Println()
		fmt.Println("Next steps (as described in paper):")
		fmt.Println("• Hash ClientHello: Hash(α·G)")
		fmt.Println("• Hash ServerHello: Hash(β·G)")
		fmt.Println("• Compute KDF in SMPC using:")
		fmt.Println("  - Shares of αβ·G")
		fmt.Println("  - Hash(α·G)")
		fmt.Println("  - Hash(β·G)")
		fmt.Println("• Output: TLS handshake keys as secret-shares")
	} else {
		fmt.Println("✗ Error! Shared secrets do not match.")
	}

	// Demonstrate the additive property
	fmt.Println("\n=== Mathematical Verification ===")
	fmt.Println()
	fmt.Println("Additive Secret Sharing Property:")

	// Verify α = Σαᵢ by computing it
	alpha := big.NewInt(0)
	for _, peer := range distributedClient.Peers {
		alpha.Add(alpha, peer.AlphaI)
		alpha.Mod(alpha, curveN)
	}

	// Compute α·(β·G) using reconstructed α
	reconstructedX, reconstructedY := curve.ScalarMult(tlsServer.PublicKey.X,
		tlsServer.PublicKey.Y, alpha.Bytes())
	_ = reconstructedY

	reconstructedSecret := reconstructedX.Bytes()
	if len(reconstructedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(reconstructedSecret):], reconstructedSecret)
		reconstructedSecret = padded
	}

	fmt.Printf("• Sum of all αᵢ = α (computed for verification only)\n")
	fmt.Printf("• α·(β·G) computed directly: %s\n",
		hex.EncodeToString(reconstructedSecret))
	fmt.Printf("• Σ(αᵢ·(β·G)) computed distributedly: %s\n",
		hex.EncodeToString(clientSharedSecret))

	if hex.EncodeToString(reconstructedSecret) ==
		hex.EncodeToString(clientSharedSecret) {
		fmt.Println("✓ Mathematical property verified: α·(β·G) = Σ(αᵢ·(β·G))")
	}
}
