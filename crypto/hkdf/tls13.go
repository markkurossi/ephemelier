//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
)

func ExpandTLS13(pseudorandomKey, info, out []byte) {
	expander := hmac.New(sha256.New, pseudorandomKey)
	counter := []byte{1}

	var prev []byte

	for len(out) > 0 {
		if counter[0] > 1 {
			expander.Reset()
			expander.Write(prev)
		}
		expander.Write(info)
		expander.Write(counter)
		prev = expander.Sum(prev[:0])
		counter[0]++

		n := copy(out, prev)
		out = out[n:]
	}
}
