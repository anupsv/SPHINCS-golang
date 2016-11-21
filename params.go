package SPHINCS_golang

import (
	"github.com/dchest/blake256"
)

const (
	SUBTREE_HEIGHT   = 5
	TOTALTREE_HEIGHT = 60
	N_LEVELS         = (TOTALTREE_HEIGHT / SUBTREE_HEIGHT)
	SEED_BYTES       = 32
	WOTS_LOGW        = 4
	WOTS_LogL     = 7
	WOTS_SIGBYTES = (WOTS_L*HASH_BYTES)

	SK_RAND_SEED_BYTES = 32
	MESSAGE_HASH_SEED_BYTES = 32

	HORST_LOGT    = 16
	HORST_T = (1 << HORST_LOGT)
	HORST_K       = 32
	HORST_SKBYTES = 32
	HORST_SIGBYTES = (64*HASH_BYTES+(((HORST_LOGT-6)*HASH_BYTES)+HORST_SKBYTES)*HORST_K)

	WOTS_W   = (1 << WOTS_LOGW)
	WOTS_L1  = ((256 + WOTS_LOGW - 1) / WOTS_LOGW)
	WOTS_L   = 67 // for WOTS_W == 16
	WOTS_SIGBYTES = (WOTS_L*HASH_BYTES)
	HASHSIZE = blake256.Size

	HASH_BYTES = 32 // Has to be log(HORST_T)*HORST_K/8
	MSGHASH_BYTES = 64
	HASHC        = "expand 32-byte to 64-byte state!"
	SIGMA        = "expand 32-byte k"
	TAU          = "expand 16-byte k"
	CHACHAROUNDS = 12
	N_MASKS = (2*(HORST_LOGT))

)
