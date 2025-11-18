//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package kernel

import (
	"bytes"
	"testing"
)

type marshalTest struct {
	U8   uint8
	U16  uint16
	U32  uint32
	U64  uint64
	Data []byte
}

func TestMarshalValues(t *testing.T) {
	data := &marshalTest{
		U8:   0x88,
		U16:  0x1616,
		U32:  0x32323232,
		U64:  0x6464646464646464,
		Data: []byte("Hello, world!"),
	}

	var buf [1024]byte

	n, err := MarshalTo(buf[:], &data)
	if err != nil {
		t.Fatal(err)
	}
	const marshalledSize = 1 + 2 + 4 + 8 + 4 + 13
	if n != marshalledSize {
		t.Errorf("marshalled %v, expected %v", n, marshalledSize)
	}

	var data2 marshalTest

	n2, err := UnmarshalFrom(buf[:], &data2)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != n {
		t.Errorf("unmarshalled %v, expected %v", n2, n)
	}

	if data.U32 != data2.U32 {
		t.Errorf("U32: %x, %x\n", data.U32, data.U32)
	}
	if data.U64 != data2.U64 {
		t.Errorf("U64: %x, %x\n", data.U64, data.U64)
	}
	if bytes.Compare(data.Data, data2.Data) != 0 {
		t.Errorf("Data: %x, %x\n", data.Data, data2.Data)
	}
}
