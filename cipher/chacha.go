/*
QuarkDash ChaCha20 Implementation

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package cipher

import "github.com/DevsDaddy/quarkdash-go/core"

// ChaChaKeystream - lazy keystream for ChaCha20 (64B block).
// Cache last 64 blocks, supports seek and custom offset
type ChaChaKeystream struct {
	*lazyKeystream
	key   []byte // 32B
	nonce []byte // 12B
}

// NewChaChaKeystream creates keystream (exported for tests).
func NewChaChaKeystream(key, nonce []byte) *ChaChaKeystream { return newChaChaKeystream(key, nonce) }

// newChaChaKeystream creates keystream for key/nonce.
func newChaChaKeystream(key, nonce []byte) *ChaChaKeystream {
	k := make([]byte, 32)
	n := make([]byte, 12)
	copy(k, key)
	copy(n, nonce)
	c := &ChaChaKeystream{key: k, nonce: n}
	c.lazyKeystream = newLazyKeystream(64, c.generateBlock)
	return c
}

// GenerateBlock generates a block (exported for tests).
func (c *ChaChaKeystream) GenerateBlock(blockIndex int) []byte { return c.generateBlock(blockIndex) }

// generateBlock generates one 64-bytes based block of ChaCha20 for blockIndex (counter).
// Implements RFC 7539: constants "expand 32-byte k", key 8 words, nonce 3 words, counter.
func (c *ChaChaKeystream) generateBlock(blockIndex int) []byte {
	var state [16]uint32
	// Magic constants "expand 32-byte k"
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		state[4+i] = core.ReadUint32LE(c.key, i*4)
	}
	for i := 0; i < 3; i++ {
		state[13+i] = core.ReadUint32LE(c.nonce, i*4)
	}
	state[12] = uint32(blockIndex) // counter

	var working [16]uint32
	copy(working[:], state[:])

	// quarter-round basic operation for ChaCha
	qr := func(s *[16]uint32, a, b, cc, d int) {
		s[a] += s[b]
		s[d] ^= s[a]
		s[d] = (s[d] << 16) | (s[d] >> 16)
		s[cc] += s[d]
		s[b] ^= s[cc]
		s[b] = (s[b] << 12) | (s[b] >> 20)
		s[a] += s[b]
		s[d] ^= s[a]
		s[d] = (s[d] << 8) | (s[d] >> 24)
		s[cc] += s[d]
		s[b] ^= s[cc]
		s[b] = (s[b] << 7) | (s[b] >> 25)
	}
	// 20 rounds = 10 iterations by 8 quarter-round
	for r := 0; r < 10; r++ {
		qr(&working, 0, 4, 8, 12)
		qr(&working, 1, 5, 9, 13)
		qr(&working, 2, 6, 10, 14)
		qr(&working, 3, 7, 11, 15)
		qr(&working, 0, 5, 10, 15)
		qr(&working, 1, 6, 11, 12)
		qr(&working, 2, 7, 8, 13)
		qr(&working, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		working[i] += state[i]
	}
	out := make([]byte, 64)
	for i := 0; i < 16; i++ {
		core.WriteUint32LE(working[i], out, i*4)
	}
	return out
}

// QuarkDashChaCha - symmetric ChaCha20 cipher with lazy keystream.
// Key 32B, nonce 12B, encrypt/decrypt - XOR with keystream.
type QuarkDashChaCha struct {
	key   []byte
	nonce []byte
}

// NewQuarkDashChaCha создаёт шифр ChaCha20.
func NewQuarkDashChaCha(key, nonce []byte) (*QuarkDashChaCha, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(nonce) != 12 {
		return nil, ErrInvalidNonceSize
	}
	k := make([]byte, 32)
	n := make([]byte, 12)
	copy(k, key)
	copy(n, nonce)
	return &QuarkDashChaCha{key: k, nonce: n}, nil
}

// Encrypt encrypts data  (XOR with keystream, symmetric).
func (q *QuarkDashChaCha) Encrypt(data []byte) []byte { return q.process(data) }

// Decrypt decrypt data (symmetric to Encrypt).
func (q *QuarkDashChaCha) Decrypt(data []byte) []byte { return q.process(data) }

// CreateKeystream return lazy keystream for custom access.
func (q *QuarkDashChaCha) CreateKeystream() *ChaChaKeystream {
	return newChaChaKeystream(q.key, q.nonce)
}

// GetKeystreamBytes return a slice from keystream with offset.
func (q *QuarkDashChaCha) GetKeystreamBytes(offset, length int) []byte {
	return q.CreateKeystream().GetBytes(offset, length)
}

// ProcessWithOffset encrypt with keystream offset.
func (q *QuarkDashChaCha) ProcessWithOffset(data []byte, offset int) []byte {
	return q.CreateKeystream().Xor(data, offset)
}

func (q *QuarkDashChaCha) process(data []byte) []byte {
	return q.CreateKeystream().Xor(data, 0)
}
