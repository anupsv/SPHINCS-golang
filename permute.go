package SPHINCS_golang

import "encoding/binary"

func permute(buf *[64]byte) {
	var x [16]uint32
	for i := 0; i < len(x); i++ {
		x[i] = binary.LittleEndian.Uint32(buf[4*i:])
	}
	doRounds(&x)
	// for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]); // XXX: Bad idea if we later xor the input to the state?
	for i := 0; i < len(x); i++ {
		binary.LittleEndian.PutUint32(buf[4*i:], x[i])
	}
}
