//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (

	// "github.com/bytemare/ecc"
	// "github.com/bytemare/secret-sharing/keys"

	"github.com/bytemare/dkg"
	"github.com/bytemare/frost"
)

var (
	ciphersuite = frost.Default
	c           = dkg.Ristretto255Sha512
)
