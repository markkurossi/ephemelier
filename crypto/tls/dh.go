//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

func (conn *Conn) stdDH(peerPub []byte) ([]byte, []byte, error) {
	ecdhCurve := ecdh.P256()
	ecdhPriv, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, conn.internalErrorf("error creating private key: %v",
			err)
	}

	// Decode client's public key.
	ecdhClientPub, err := ecdhCurve.NewPublicKey(peerPub)
	if err != nil {
		return nil, nil, conn.decodeErrorf("invalid client public key: %v", err)
	}
	sharedSecret, err := ecdhPriv.ECDH(ecdhClientPub)
	if err != nil {
		return nil, nil, conn.decodeErrorf("ECDH failed: %v", err)
	}

	return sharedSecret, ecdhPriv.PublicKey().Bytes(), nil
}

func (conn *Conn) mpcDH(peerPub []byte) ([]byte, []byte, error) {
	// Decode peer's public key.
	if len(peerPub) != 65 || peerPub[0] != 0x04 {
		fmt.Printf("*** pub:\n%s", hex.Dump(peerPub))
		return nil, nil, conn.decodeErrorf("invalid client public key")
	}
	peerX := new(big.Int).SetBytes(peerPub[1:33])
	peerY := new(big.Int).SetBytes(peerPub[33:65])

	peerPublicKey := &Point{
		X: peerX,
		Y: peerY,
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
			peer.PubKey.X, peer.PubKey.Y)
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

	fmt.Println("Partial DH Computations:")
	for i, peer := range dhPeers {
		partial := peer.ComputePartialDH(peerPublicKey)
		partialResults[i] = partial
		fmt.Printf(" • %s computes αᵢ·(β·G): (%s..., %s...)\n",
			peer.Name,
			hex.EncodeToString(partial.X.Bytes())[:16],
			hex.EncodeToString(partial.Y.Bytes())[:16])
	}

	// MPC engine computes αβ·G = Σ(αᵢ·(β·G))

	fmt.Println("SMPC Engine Combining Results:")
	finalX := big.NewInt(0)
	finalY := big.NewInt(0)

	for i, partial := range partialResults {
		finalX, finalY = curveAdd(finalX, finalY, partial.X, partial.Y)
		fmt.Printf(" • Added contribution from DHPeer%d\n", i)
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
	PubKey *Point   // Public key share: αᵢ·G
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
		PubKey: &Point{X: pubX, Y: pubY},
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
