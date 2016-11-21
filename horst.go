package SPHINCS_golang


import "github.com/dchest/blake512"

func expandseed(outseeds []byte, inseed *[SEED_BYTES]byte) {
//	outseeds = outseeds[:T*SkBytes]
	prg(outseeds[0:HORST_T * HORST_SKBYTES], inseed[:])
}

func sign(sig []byte, pk *[HASHSIZE]byte, m []byte, seed *[SEED_BYTES]byte, masks []byte, mHash []byte) {
//	masks = masks[:2*LogT*HASHSIZE]
//	mHash = mHash[:hash.MsgSize]

	var sk [HORST_T * HORST_SKBYTES]byte
	sigpos := 0

	expandseed(sk[:], seed)

	// Build the whole tree and save it.
	var tree [(2* HORST_T - 1) * HASHSIZE]byte // replace by something more memory-efficient?

	// Generate pk leaves.
	for i := 0; i < HORST_T; i++ {
		Hash_n_n(tree[(HORST_T -1+i)*HASHSIZE:], sk[i* HORST_SKBYTES:])
	}

	var offsetIn, offsetOut uint64
	for i := uint(0); i < HORST_LOGT; i++ {
		offsetIn = (1 << (HORST_LOGT - i)) - 1
		offsetOut = (1 << (HORST_LOGT - i - 1)) - 1
		for j := uint64(0); j < 1<<(HORST_LOGT -i-1); j++ {
			Hash_2n_n_mask(tree[(offsetOut+j)*HASHSIZE:], tree[(offsetIn+2*j)*HASHSIZE:], masks[2*i*HASHSIZE:])
		}
	}

	// First write 64 hashes from level 10 to the signature.
	copy(sig[0:64*HASHSIZE], tree[63*HASHSIZE:127*HASHSIZE])
	sigpos += 64 * HASHSIZE

	// Signature consists of horstK parts; each part of secret key and
	// LogT-4 auth-path hashes.
	for i := 0; i < HORST_K; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)

		copy(sig[sigpos:sigpos+ HORST_SKBYTES], sk[idx* HORST_SKBYTES:(idx+1)* HORST_SKBYTES])
		sigpos += HORST_SKBYTES

		idx += HORST_T - 1
		for j := 0; j < HORST_LOGT -6; j++ {
			// neighbor node
			if idx&1 != 0 {
				idx = idx + 1
			} else {
				idx = idx - 1
			}
			copy(sig[sigpos:sigpos+HASHSIZE], tree[idx*HASHSIZE:(idx+1)*HASHSIZE])
			sigpos += HASHSIZE
			idx = (idx - 1) / 2 // parent node
		}
	}

	copy(pk[0:HASHSIZE], tree[0:HASHSIZE])
}

func Verify(pk, sig, m, masks, mHash []byte) int {
//	masks = masks[:2*LogT*HASHSIZE]
//	mHash = mHash[:hash.MsgSize]

	// XXX/Yawning: I have no idea why this has a clear cutfail case and a
	// return value if the calling code doesn't ever actually check it.
	var buffer [32 * HASHSIZE]byte
	level10 := sig
	sig = sig[64*HASHSIZE:]

	for i := 0; i < HORST_K; i++ {
		idx := uint(mHash[2*i]) + (uint(mHash[2*i+1]) << 8)

		if idx&1 == 0 {
			Hash_n_n(buffer[:], sig)
			copy(buffer[HASHSIZE:HASHSIZE*2], sig[HORST_SKBYTES:HORST_SKBYTES +HASHSIZE])
		} else {
			Hash_n_n(buffer[HASHSIZE:], sig)
			copy(buffer[0:HASHSIZE], sig[HORST_SKBYTES:HORST_SKBYTES +HASHSIZE])
		}
		sig = sig[HORST_SKBYTES +HASHSIZE:]

		for j := 1; j < HORST_LOGT -6; j++ {
			idx = idx >> 1 // parent node

			if idx&1 == 0 {
				Hash_2n_n_mask(buffer[:], buffer[:], masks[2*(j-1)*HASHSIZE:])
				copy(buffer[HASHSIZE:HASHSIZE*2], sig[0:HASHSIZE])
			} else {
				Hash_2n_n_mask(buffer[HASHSIZE:], buffer[:], masks[2*(j-1)*HASHSIZE:])
				copy(buffer[0:HASHSIZE], sig[0:HASHSIZE])
			}
			sig = sig[HASHSIZE:]
		}

		idx = idx >> 1 // parent node
		Hash_2n_n_mask(buffer[:], buffer[:], masks[2*(HORST_LOGT -7)*HASHSIZE:])

		for k := uint(0); k < HASHSIZE; k++ {
			if level10[idx*HASHSIZE+k] != buffer[k] {
				goto fail
			}
		}
	}

	// Compute root from level10
	for j := 0; j < 32; j++ {
		Hash_2n_n_mask(buffer[j*HASHSIZE:], level10[2*j*HASHSIZE:], masks[2*(HORST_LOGT -6)*HASHSIZE:])
	}
	// Hash from level 11 to 12
	for j := 0; j < 16; j++ {
		Hash_2n_n_mask(buffer[j*HASHSIZE:], buffer[2*j*HASHSIZE:], masks[2*(HORST_LOGT -5)*HASHSIZE:])
	}
	// Hash from level 12 to 13
	for j := 0; j < 8; j++ {
		Hash_2n_n_mask(buffer[j*HASHSIZE:], buffer[2*j*HASHSIZE:], masks[2*(HORST_LOGT -4)*HASHSIZE:])
	}
	// Hash from level 13 to 14
	for j := 0; j < 4; j++ {
		Hash_2n_n_mask(buffer[j*HASHSIZE:], buffer[2*j*HASHSIZE:], masks[2*(HORST_LOGT -3)*HASHSIZE:])
	}
	// Hash from level 14 to 15
	for j := 0; j < 2; j++ {
		Hash_2n_n_mask(buffer[j*HASHSIZE:], buffer[2*j*HASHSIZE:], masks[2*(HORST_LOGT -2)*HASHSIZE:])
	}
	// Hash from level 15 to 16
	Hash_2n_n_mask(pk, buffer[:], masks[2*(HORST_LOGT -1)*HASHSIZE:])

	return 0

fail:
	zerobytes(pk[0:HASHSIZE])
	return -1
}

func init() {
	if HORST_SKBYTES != HASHSIZE {
		panic("need to have HORST_SKBYTES == HASH_BYTES")
	}
	if HORST_K != blake512.Size/2 {
		panic("need to have HORST_K == MSGHASH_BYTES/2")
	}
}
