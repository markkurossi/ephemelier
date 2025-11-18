//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"math/big"
)

// P256 curve parameters (secp256r1 / prime256v1)
var (
	// Prime field: y² = x³ - 3x + b (mod p)
	p256P, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	p256A, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16) // -3 mod p
	p256B, _ = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	p256N, _ = new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16) // curve order
)

// curveAdd performs elliptic curve point addition on P256
// Adds two points (x1, y1) and (x2, y2) and returns (x3, y3)
// Handles special cases: point at infinity, point doubling
func curveAdd(x1, y1, x2, y2 *big.Int) (x3, y3 *big.Int) {
	x3 = new(big.Int)
	y3 = new(big.Int)

	// Case 1: If P1 is the point at infinity (0, 0), return P2
	if x1.Sign() == 0 && y1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		return
	}

	// Case 2: If P2 is the point at infinity (0, 0), return P1
	if x2.Sign() == 0 && y2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		return
	}

	// Case 3: If x1 == x2 and y1 == -y2 (mod p), result is point at infinity
	negY2 := new(big.Int).Neg(y2)
	negY2.Mod(negY2, p256P)
	if x1.Cmp(x2) == 0 && y1.Cmp(negY2) == 0 {
		x3.SetInt64(0)
		y3.SetInt64(0)
		return
	}

	// Case 4: Point doubling (x1 == x2 and y1 == y2)
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return curveDouble(x1, y1)
	}

	// Case 5: Standard point addition (P1 != P2)
	// Calculate slope λ = (y2 - y1) / (x2 - x1) mod p

	// numerator = y2 - y1
	numerator := new(big.Int).Sub(y2, y1)
	numerator.Mod(numerator, p256P)

	// denominator = x2 - x1
	denominator := new(big.Int).Sub(x2, x1)
	denominator.Mod(denominator, p256P)

	// λ = numerator * denominator^(-1) mod p
	denominatorInv := new(big.Int).ModInverse(denominator, p256P)
	lambda := new(big.Int).Mul(numerator, denominatorInv)
	lambda.Mod(lambda, p256P)

	// x3 = λ² - x1 - x2 mod p
	x3.Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p256P)

	// y3 = λ(x1 - x3) - y1 mod p
	y3.Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, p256P)

	return
}

// curveDouble performs elliptic curve point doubling on P256
// Doubles point (x, y) and returns (x3, y3)
func curveDouble(x, y *big.Int) (x3, y3 *big.Int) {
	x3 = new(big.Int)
	y3 = new(big.Int)

	// Handle point at infinity
	if x.Sign() == 0 && y.Sign() == 0 {
		x3.SetInt64(0)
		y3.SetInt64(0)
		return
	}

	// Calculate slope λ = (3x² + a) / (2y) mod p
	// For P256: a = -3

	// numerator = 3x² + a
	numerator := new(big.Int).Mul(x, x)
	numerator.Mul(numerator, big.NewInt(3))
	numerator.Add(numerator, p256A)
	numerator.Mod(numerator, p256P)

	// denominator = 2y
	denominator := new(big.Int).Mul(y, big.NewInt(2))
	denominator.Mod(denominator, p256P)

	// λ = numerator * denominator^(-1) mod p
	denominatorInv := new(big.Int).ModInverse(denominator, p256P)
	lambda := new(big.Int).Mul(numerator, denominatorInv)
	lambda.Mod(lambda, p256P)

	// x3 = λ² - 2x mod p
	x3.Mul(lambda, lambda)
	x3.Sub(x3, x)
	x3.Sub(x3, x)
	x3.Mod(x3, p256P)

	// y3 = λ(x - x3) - y mod p
	y3.Sub(x, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y)
	y3.Mod(y3, p256P)

	return
}
