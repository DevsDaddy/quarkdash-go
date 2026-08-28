/*
QuarkDash Cipher Base

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package cipher

import "errors"

// CipherType define a type of symmetric cipher
type CipherType int

const (
	// CipherChaCha20 - Use ChaCha20 Implementation (RFC 7539), 64B block, 20 rounds
	CipherChaCha20 CipherType = 0
	// CipherGimli - lightweight Gimli, 48B block, 24 rounds, optimal for IoT
	CipherGimli CipherType = 1
)

// Errors
var (
	ErrInvalidKeySize    = errors.New("key must be 32 bytes")
	ErrInvalidNonceSize  = errors.New("nonce must be 12 bytes")
	ErrUnsupportedCipher = errors.New("unsupported cipher type")
)

// Cipher an interface for symmetric cipher (XOR with keystream)
type Cipher interface {
	Encrypt(data []byte) []byte
	Decrypt(data []byte) []byte
}

// NewCipher creates cipher by type with key (32B) and nonce (12B)
func NewCipher(ct CipherType, key, nonce []byte) (Cipher, error) {
	switch ct {
	case CipherChaCha20:
		return NewQuarkDashChaCha(key, nonce)
	case CipherGimli:
		return NewQuarkDashGimli(key, nonce)
	default:
		return nil, ErrUnsupportedCipher
	}
}

// mustCipher create panic when error
// it uses inside a protocol, where the data is validated
func mustCipher(ct CipherType, key, nonce []byte) Cipher {
	c, err := NewCipher(ct, key, nonce)
	if err != nil {
		panic(err)
	}
	return c
}
