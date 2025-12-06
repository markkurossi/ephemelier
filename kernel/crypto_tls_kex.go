//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/markkurossi/ephemelier/crypto/tls"
)

// DHPeer represents a MPC DH peer with its share of the private key.
type DHPeer struct {
	Name   string
	Curve  elliptic.Curve
	AlphaI *big.Int // Private key share: αᵢ
	Pubkey *Point   // Public key share: αᵢ·G
}

// NewDHPeer creates a new MPC DH peer with a random key share.
func NewDHPeer(name string, curve elliptic.Curve) (*DHPeer, error) {
	// Sample αᵢ ← Z_p+
	alphaI, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("failed to generate alphaI for %s: %w",
			name, err)
	}

	// Compute αᵢ·G
	pubX, pubY := curve.ScalarBaseMult(alphaI.Bytes())

	return &DHPeer{
		Name:   name,
		Curve:  curve,
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
	partialX, partialY := p.Curve.ScalarMult(peerPublicKey.X, peerPublicKey.Y,
		p.AlphaI.Bytes())

	return &Point{
		X: partialX,
		Y: partialY,
	}
}

// DecodePublicKey decodes the serialized P-256 public key. The public
// key must be encoded in the SEC 1 uncompressed point format.
func DecodePublicKey(data []byte) (*Point, error) {
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

// Point represents an elliptic curve point.
type Point struct {
	X, Y *big.Int
}
