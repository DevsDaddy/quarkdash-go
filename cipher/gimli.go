/*
QuarkDash Gimli Implementation

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package cipher

import "github.com/DevsDaddy/quarkdash-go/core"

// GimliKeystream - lazy keystream based on Gimli cipher (48B block).
// Great for IoT and small devices, use cache and seekable.
type GimliKeystream struct {
	*lazyKeystream
	key   []byte
	nonce []byte
}

func NewGimliKeystream(key, nonce []byte) *GimliKeystream { return newGimliKeystream(key, nonce) }

func newGimliKeystream(key, nonce []byte) *GimliKeystream {
	k := make([]byte, 32)
	n := make([]byte, 12)
	copy(k, key)
	copy(n, nonce)
	g := &GimliKeystream{key: k, nonce: n}
	g.lazyKeystream = newLazyKeystream(48, g.generateBlock)
	return g
}

// GenerateBlock generates block (for tests).
func (g *GimliKeystream) GenerateBlock(blockIndex int) []byte { return g.generateBlock(blockIndex) }

// generateBlock generates 48-bytes Gimli block.
// State 12 words: 8 key words, 3 nonce words, 1 counter words for block.
func (g *GimliKeystream) generateBlock(blockIndex int) []byte {
	var state [12]uint32
	for i := 0; i < 8; i++ {
		state[i] = core.ReadUint32LE(g.key, i*4)
	}
	state[8] = core.ReadUint32LE(g.nonce, 0)
	state[9] = core.ReadUint32LE(g.nonce, 4)
	state[10] = core.ReadUint32LE(g.nonce, 8)
	state[11] = uint32(blockIndex)

	var w [12]uint32
	copy(w[:], state[:])
	// 24 rounds for Gimli
	for round := 0; round < 24; round++ {
		for i := 0; i < 4; i++ {
			x := w[i]
			y := w[i+4]
			z := w[i+8]
			w[i] = x ^ (z << 1) ^ ((y & z) << 2)
			w[i+4] = y ^ x ^ ((x | z) << 1)
			w[i+8] = z ^ y ^ ((x & y) << 3)
		}
		// XOR
		t := w[1]
		w[1] = w[2]
		w[2] = w[3]
		w[3] = t
		if (round & 3) == 0 {
			w[0] ^= 0x9e377900 | uint32(round)
		}
	}
	out := make([]byte, 48)
	for i := 0; i < 12; i++ {
		core.WriteUint32LE(w[i], out, i*4)
	}
	return out
}

// QuarkDashGimli - symmetric Gimli cipher (lightweight, 48B block).
type QuarkDashGimli struct {
	key   []byte
	nonce []byte
}

// NewQuarkDashGimli creates Gimli cipher.
func NewQuarkDashGimli(key, nonce []byte) (*QuarkDashGimli, error) {
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
	return &QuarkDashGimli{key: k, nonce: n}, nil
}

// Encrypt encrypt data with XOR and keystream.
func (q *QuarkDashGimli) Encrypt(data []byte) []byte { return q.process(data) }

// Decrypt decrypt data (symmetric to Encrypt).
func (q *QuarkDashGimli) Decrypt(data []byte) []byte { return q.process(data) }

// CreateKeystream return lazy keystream.
func (q *QuarkDashGimli) CreateKeystream() *GimliKeystream {
	return newGimliKeystream(q.key, q.nonce)
}

// GetKeystreamBytes return slice from keystream.
func (q *QuarkDashGimli) GetKeystreamBytes(offset, length int) []byte {
	return q.CreateKeystream().GetBytes(offset, length)
}

// ProcessWithOffset encrypt with offset.
func (q *QuarkDashGimli) ProcessWithOffset(data []byte, offset int) []byte {
	return q.CreateKeystream().Xor(data, offset)
}

func (q *QuarkDashGimli) process(data []byte) []byte {
	return q.CreateKeystream().Xor(data, 0)
}
