package main

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/markkurossi/mpc/p2p"
)

// auditTriples is optional debugging logic. For now we provide
// a stub that does no auditing unless you explicitly request it.
func auditTriples(conn *p2p.Conn, id int,
	triples []*Triple, auditRate float64) error {

	if auditRate <= 0 {
		return nil
	}

	// If audit is requested but not implemented:
	return errors.New("triple auditing not implemented")
}

// If you'd like deterministic sampling or real audits,
// we can replace this stub with the full implementation.
// For completeness you can add this helper now:

func sampleIndices(n, k int) []int {
	if k <= 0 {
		return nil
	}
	seen := make(map[int]bool)
	var out []int
	for len(out) < k {
		x, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
		i := int(x.Int64())
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}
