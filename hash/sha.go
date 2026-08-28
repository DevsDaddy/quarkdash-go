/*
    QuarkDash SHA Implementation

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// SHA256 Hash helper based on stdlib
func SHA256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	out := make([]byte, 32)
	copy(out, h[:])
	return out
}

// SHA256 HEX helper
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA512 Hash helper based on stdlib
func SHA512Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	out := make([]byte, 64)
	copy(out, h[:])
	return out
}

// SHA512 HEX Helper
func SHA512Hex(data []byte) string {
	h := sha512.Sum512(data)
	return hex.EncodeToString(h[:])
}
