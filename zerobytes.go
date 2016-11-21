package SPHINCS_golang



func zerobytes(r []byte) []byte {
	for i := 0; i < len(r); i++ {
		r[i] = 0
	}
	return r
}