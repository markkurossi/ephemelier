//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

func decodePublicKey(data []byte) (*Point, error) {
	if len(data) != 65 || data[0] != 0x04 {
		return nil, tls.AlertDecodeError
	}
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])

	return &Point{
		X: x,
		Y: y,
	}, nil
}

func (proc *Process) mpcDH(peerPub []byte) ([]byte, []byte, error) {
	// Decode peer's public key.
	peerPublicKey, err := decodePublicKey(peerPub)
	if err != nil {
		return nil, nil, err
	}

	const numShares = 2
	dhPeers := make([]*DHPeer, numShares)

	// Step 1.1: Each server Pᵢ samples αᵢ and computes αᵢ·G
	for i := 0; i < numShares; i++ {
		dhPeer, err := NewDHPeer(fmt.Sprintf("DHPeer%d", i))
		if err != nil {
			return nil, nil, err
		}
		dhPeers[i] = dhPeer
	}

	// Step 1.2: P1 (forwarding server) computes α·G = Σ(αᵢ·G) - our
	// public key.
	pubkeyX := big.NewInt(0)
	pubkeyY := big.NewInt(0)

	for _, peer := range dhPeers {
		pubkeyX, pubkeyY = curve.Add(pubkeyX, pubkeyY,
			peer.Pubkey.X, peer.Pubkey.Y)
	}

	// Encode public key into uncompressed SEC 1 format.

	pubkey := make([]byte, 65)
	pubkey[0] = 0x04

	xBytes := pubkeyX.Bytes()
	copy(pubkey[1+32-len(xBytes):], xBytes)

	yBytes := pubkeyY.Bytes()
	copy(pubkey[1+64-len(yBytes):], yBytes)

	// Step 2: Each party Pᵢ computes αᵢ·(β·G)

	partialResults := make([]*Point, len(dhPeers))

	proc.debugf("Partial DH Computations:\n")
	for i, peer := range dhPeers {
		partial := peer.ComputePartialDH(peerPublicKey)
		partialResults[i] = partial
		proc.debugf(" • %s computes αᵢ·(β·G): (%s..., %s...)\n",
			peer.Name,
			hex.EncodeToString(partial.X.Bytes())[:16],
			hex.EncodeToString(partial.Y.Bytes())[:16])
	}

	// MPC engine computes αβ·G = Σ(αᵢ·(β·G))

	proc.debugf("SMPC Engine Combining Results:\n")
	finalX := big.NewInt(0)
	finalY := big.NewInt(0)

	for i, partial := range partialResults {
		finalX, finalY = curveAdd(finalX, finalY, partial.X, partial.Y)
		proc.debugf(" • Added contribution from DHPeer%d\n", i)
	}

	// Use X-coordinate as shared secret (standard ECDH practice)
	sharedSecret := finalX.Bytes()

	// Pad to 32 bytes if necessary
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	return sharedSecret, pubkey, nil
}

// P256 curve parameters.
var (
	curve       = elliptic.P256()
	curveParams = curve.Params()
)

// Point represents an elliptic curve point.
type Point struct {
	X, Y *big.Int
}

// DHPeer represents a MPC DH peer with its share of the private key.
type DHPeer struct {
	Name   string
	AlphaI *big.Int // Private key share: αᵢ
	Pubkey *Point   // Public key share: αᵢ·G
}

// NewDHPeer creates a new MPC DH peer with a random key share.
func NewDHPeer(name string) (*DHPeer, error) {
	// Sample αᵢ ← Z_p+
	alphaI, err := rand.Int(rand.Reader, curveParams.N)
	if err != nil {
		return nil, fmt.Errorf("failed to generate alphaI for %s: %w",
			name, err)
	}

	// Compute αᵢ·G
	pubX, pubY := curve.ScalarBaseMult(alphaI.Bytes())

	return &DHPeer{
		Name:   name,
		AlphaI: alphaI,
		Pubkey: &Point{
			X: pubX,
			Y: pubY,
		},
	}, nil
}

// ComputePartialDH computes αᵢ·(β·G) - the peer's contribution to the
// DH result.
func (p *DHPeer) ComputePartialDH(peerPublicKey *Point) *Point {
	// Compute αᵢ·(β·G)
	partialX, partialY := curve.ScalarMult(peerPublicKey.X, peerPublicKey.Y,
		p.AlphaI.Bytes())

	return &Point{
		X: partialX,
		Y: partialY,
	}
}
