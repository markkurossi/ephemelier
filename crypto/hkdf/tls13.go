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

var (
	ZeroHashTLS13  = make([]byte, sha256.Size)
	EmptyHashTLS13 = []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	}
)

func ExtractTLS13(secret, salt []byte) []byte {
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	return extractor.Sum(nil)
}

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
