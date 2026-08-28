/*
QuarkDash KDF Implementation

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package core

// Use hash helpers
import "github.com/DevsDaddy/quarkdash-go/hash"

// KDF Interface for keys derive (HKDF-like)
type KDF interface {
	Derive(ikm, salt, info []byte, length int) []byte
}

/*
QuarkDash KDF Implementation based on SHAKE256
Algorythm:
1) PRK = SHAKE256(salt||IKM, 64)
2) HKDF-Expand with info and counter
*/
type QuarkDashKDF struct{}

/*
Derive Method compute HKDF-Expand with SHAKE256
*/
func (k *QuarkDashKDF) Derive(ikm, salt, info []byte, length int) []byte {
	// PRK pseudo-random key from salt and IKM
	prk := hash.Shake256(ConcatBytes(salt, ikm), 64)
	result := make([]byte, length)
	var t []byte
	offset := 0
	i := 1
	// Iterative Expand: T = SHAKE256(PRK||T_prev||info||i)
	for offset < length {
		input := ConcatBytes(t, info, []byte{byte(i)})
		t = hash.Shake256(ConcatBytes(prk, input), 64)
		take := 64
		if length-offset < take {
			take = length - offset
		}
		copy(result[offset:], t[:take])
		offset += take
		i++
	}
	SecureZero(t)
	return result
}
