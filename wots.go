package SPHINCS_golang

func expandSeed(outseeds []byte, inseed []byte) {
	prg(outseeds[0:WOTS_L* HASHSIZE], inseed[0:SEED_BYTES])
}

func genChain(out, seed []byte, masks []byte, chainlen int) {
	copy(out[0:HASHSIZE], seed[0:HASHSIZE])
	for i := 0; i < chainlen && i < WOTS_W; i++ {
		mask := masks[i* HASHSIZE:]
		Hash_n_n_mask(out[:], out[:], mask)
	}
}

func pkgen(pk []byte, sk []byte, masks []byte) {

	expandSeed(pk, sk)
	for i := 0; i < WOTS_L; i++ {
		genChain(pk[i* HASHSIZE:], pk[i* HASHSIZE:], masks, WOTS_W-1)
	}
}

func Sign(sig []byte, msg *[HASHSIZE]byte, sk *[SEED_BYTES]byte, masks []byte) {
	//	sig = sig[:L*SIZE]
	//	masks = masks[:(W-1)*SIZE]

	var basew [WOTS_L]int
	var c, i int
	switch WOTS_W {
	case 16:
		for i = 0; i < WOTS_L1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += WOTS_W - 1 - basew[i]
			c += WOTS_W - 1 - basew[i+1]
		}
		for ; i < WOTS_L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		expandSeed(sig, sk[:])
		for i = 0; i < WOTS_L; i++ {
			genChain(sig[i* HASHSIZE:], sig[i* HASHSIZE:], masks, basew[i])
		}
	case 4:
		for i = 0; i < WOTS_L1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += WOTS_W - 1 - basew[i]
			c += WOTS_W - 1 - basew[i+1]
			c += WOTS_W - 1 - basew[i+2]
			c += WOTS_W - 1 - basew[i+3]
		}
		for ; i < WOTS_L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		expandSeed(sig, sk[:])
		for i = 0; i < WOTS_L; i++ {
			genChain(sig[i* HASHSIZE:], sig[i* HASHSIZE:], masks, basew[i])
		}
	default:
		panic("not yet implemented")
	}
}

func verify(pk *[WOTS_L * HASHSIZE]byte, sig []byte, msg *[HASHSIZE]byte, masks []byte) {
	//	sig = sig[:L*SIZE]
	//	masks = masks[:(W-1)*SIZE]

	var basew [WOTS_L]int
	var c, i int
	switch WOTS_W {
	case 16:
		for i = 0; i < WOTS_L1; i += 2 {
			basew[i] = int(msg[i/2] & 0xf)
			basew[i+1] = int(msg[i/2] >> 4)
			c += WOTS_W - 1 - basew[i]
			c += WOTS_W - 1 - basew[i+1]
		}
		for ; i < WOTS_L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		for i = 0; i < WOTS_L; i++ {
			genChain(pk[i* HASHSIZE:], sig[i* HASHSIZE:], masks[basew[i]* HASHSIZE:], WOTS_W-1-basew[i])
		}
	case 4:
		for i = 0; i < WOTS_L1; i += 4 {
			basew[i] = int(msg[i/4] & 0x3)
			basew[i+1] = int((msg[i/4] >> 2) & 0x3)
			basew[i+2] = int((msg[i/4] >> 4) & 0x3)
			basew[i+3] = int((msg[i/4] >> 6) & 0x3)
			c += WOTS_W - 1 - basew[i]
			c += WOTS_W - 1 - basew[i+1]
			c += WOTS_W - 1 - basew[i+2]
			c += WOTS_W - 1 - basew[i+3]
		}
		for ; i < WOTS_L; i++ {
			basew[i] = c & 0xf
			c >>= 4
		}

		for i = 0; i < WOTS_L; i++ {
			genChain(pk[i* HASHSIZE:], sig[i* HASHSIZE:], masks[basew[i]* HASHSIZE:], WOTS_W-1-basew[i])
		}
	default:
		panic("not yet implemented")
	}
}
