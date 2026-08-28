/*
QuarkDash SHAKE Implementation

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package hash

import "crypto/sha3"

/*
Shake256 with XOF (FIPS 202) Helper
Uses stdlib crypto/sha3
*/
func Shake256(input []byte, outputLen int) []byte {
	h := sha3.NewSHAKE256()
	_, _ = h.Write(input)
	out := make([]byte, outputLen)
	_, _ = h.Read(out)
	return out
}
