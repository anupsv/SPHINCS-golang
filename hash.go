package SPHINCS_golang

import (
	"github.com/dchest/blake256"
)


func Varlen(out, in []byte) {
	h := blake256.New()
	h.Write(in)
	tmp := h.Sum(nil)
	copy(out[:], tmp[:])
	zerobytes(tmp[:])
}

func Hash_2n_n(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = HASHC[i]
	}
	permute(&x)
	for i := 0; i < 32; i++ {
		x[i] ^= in[i+32]
	}
	permute(&x)
	copy(out[:HASHSIZE], x[:])
}

func Hash_2n_n_mask(out, in, mask []byte) {
	var buf [2 * HASHSIZE]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	Hash_2n_n(out, buf[:])
}

func Hash_n_n(out, in []byte) {
	var x [64]byte
	for i := 0; i < 32; i++ {
		x[i] = in[i]
		x[i+32] = HASHC[i]
	}
	permute(&x)
	copy(out[:HASHSIZE], x[:])
}

func Hash_n_n_mask(out, in, mask []byte) {
	var buf [HASHSIZE]byte
	for i := 0; i < len(buf); i++ {
		buf[i] = in[i] ^ mask[i]
	}
	Hash_n_n(out, buf[:])
}

func init() {
	if HASHSIZE != 32 {
		panic("current code only supports 32-byte hashes")
	}
}
