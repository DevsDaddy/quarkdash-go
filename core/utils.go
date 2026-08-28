/*
QuarkDash Utils

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package core

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
)

// ConcatBytes join a different sliced into one with single memory allocation
// Skip nil-slices. Used everywhere to build input for KDF/MAC
func ConcatBytes(arrays ...[]byte) []byte {
	total := 0
	for _, a := range arrays {
		if a != nil {
			total += len(a)
		}
	}
	res := make([]byte, total)
	pos := 0
	for _, a := range arrays {
		if a != nil {
			copy(res[pos:], a)
			pos += len(a)
		}
	}
	return res
}

// TextToBytes covert string to UTF-8 bytes
func TextToBytes(s string) []byte { return []byte(s) }

// BytesToText covert bytes into string
func BytesToText(b []byte) string { return string(b) }

// BytesToHex encode bytes into HEX-string with lowercase
func BytesToHex(b []byte) string { return hex.EncodeToString(b) }

// HexToBytes decode HEX-string
func HexToBytes(s string) ([]byte, error) { return hex.DecodeString(s) }

// RandomBytes returns random bytes (crypto-secured).
func RandomBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

// SecureZero erase memory with zeros (key-leak protection at RAM).
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConstantTimeEqual equal two slices using constant time (timing-attack security).
func ConstantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ReadUint32LE read little-endian uint32 using offset
func ReadUint32LE(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

// WriteUint32LE write little-endian uint32
func WriteUint32LE(v uint32, b []byte, off int) { binary.LittleEndian.PutUint32(b[off:], v) }

// ReadUint32 read uint32 little-endian manually
func ReadUint32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// WriteUint32 writes uint32 little-endian manually
func WriteUint32(v uint32, b []byte, off int) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

// ReadUint64LE reads little-endian uint64
func ReadUint64LE(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }
