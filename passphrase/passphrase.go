/*
    QuarkDash Passphrase Implementation

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package passphrase

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/DevsDaddy/quarkdash-go/core"
	"github.com/DevsDaddy/quarkdash-go/hash"
)

// hmacSHA256 - manual implementation of HMAC-SHA256 for PBKDF2.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// pbkdf2Sync - PBKDF2-HMAC-SHA256 (RFC 8018), compatible with RFC 6070.
func pbkdf2Sync(password, salt []byte, iterations, dkLen int) []byte {
	if iterations < 1 {
		panic(errors.New("iterations must be >=1"))
	}
	hLen := 32
	l := (dkLen + hLen - 1) / hLen
	r := dkLen - (l-1)*hLen
	out := make([]byte, dkLen)
	for i := 1; i <= l; i++ {
		intBlock := []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		u := hmacSHA256(password, core.ConcatBytes(salt, intBlock))
		t := make([]byte, len(u))
		copy(t, u)
		for c := 1; c < iterations; c++ {
			u = hmacSHA256(password, u)
			for k := 0; k < hLen; k++ {
				t[k] ^= u[k]
			}
		}
		destPos := (i - 1) * hLen
		length := hLen
		if i == l {
			length = r
		}
		copy(out[destPos:], t[:length])
	}
	return out
}

// argon2idLiteSync - simplified memory-hard KDF based on SHAKE256.
// An idea similar with Argon2id: memory growth with random XOR
func argon2idLiteSync(password, salt []byte, memoryCost, timeCost, dkLen int) []byte {
	mCost := memoryCost
	if mCost < 8 {
		mCost = 8
	}
	tCost := timeCost
	if tCost < 1 {
		tCost = 1
	}
	blockSize := 64
	blocks := (mCost * 1024) / blockSize
	mem := make([][]byte, blocks)
	params := core.ConcatBytes(password, salt, []byte{byte(mCost & 0xff), byte((mCost >> 8) & 0xff), byte(tCost & 0xff)})
	mem[0] = hash.Shake256(core.ConcatBytes(params, []byte{0, 0, 0, 0}), blockSize)
	for i := 1; i < blocks; i++ {
		ctr := []byte{byte(i & 0xff), byte((i >> 8) & 0xff), byte((i >> 16) & 0xff), byte((i >> 24) & 0xff)}
		mem[i] = hash.Shake256(core.ConcatBytes(mem[i-1], ctr), blockSize)
	}
	for t := 0; t < tCost; t++ {
		for i := 0; i < blocks; i++ {
			pseudo := int(mem[i][0]) | int(mem[i][1])<<8 | int(mem[i][2])<<16 | int(mem[i][3])<<24
			if pseudo < 0 {
				pseudo = -pseudo
			}
			j := pseudo % blocks
			mixed := hash.Shake256(core.ConcatBytes(mem[i], mem[j], []byte{byte(t & 0xff), byte(i & 0xff)}), blockSize)
			for k := 0; k < blockSize; k++ {
				mem[i][k] ^= mixed[k]
			}
			mem[i] = hash.Shake256(mem[i], blockSize)
		}
	}
	n := 8
	if blocks < n {
		n = blocks
	}
	var cat []byte
	for i := 0; i < n; i++ {
		cat = core.ConcatBytes(cat, mem[i])
	}
	final := hash.Shake256(cat, dkLen)
	for i := 0; i < blocks; i++ {
		core.SecureZero(mem[i])
	}
	return final
}

// PassphraseOptions - an options for passphrase
type PassphraseOptions struct {
	Salt       []byte
	Iterations *int
	MemoryCost *int
	TimeCost   *int
	KeyLength  *int
	Algorithm  string // "pbkdf2" or "argon2id"
}

// GenerateSalt generates a salt with length (by default 32).
func GenerateSalt(length int) []byte {
	if length <= 0 {
		length = 32
	}
	return core.RandomBytes(length)
}

// PBKDF2Sync - PBKDF2 for password string
func PBKDF2Sync(passphrase string, salt []byte, iterations, dkLen int) []byte {
	return pbkdf2Sync([]byte(passphrase), salt, iterations, dkLen)
}

// PBKDF2SyncBytes - PBKDF2 for bytes based password
func PBKDF2SyncBytes(passphrase, salt []byte, iterations, dkLen int) []byte {
	return pbkdf2Sync(passphrase, salt, iterations, dkLen)
}

// Argon2idSync - Argon2id-lite for string
func Argon2idSync(passphrase string, salt []byte, memoryCost, timeCost, dkLen int) []byte {
	return argon2idLiteSync([]byte(passphrase), salt, memoryCost, timeCost, dkLen)
}

// Argon2idSyncBytes - Argon2id-lite for bytes
func Argon2idSyncBytes(passphrase, salt []byte, memoryCost, timeCost, dkLen int) []byte {
	return argon2idLiteSync(passphrase, salt, memoryCost, timeCost, dkLen)
}

// DerivePassphrase - universal derive (pbkdf2/argon2id).
func DerivePassphrase(passphrase string, opts PassphraseOptions) (key, salt []byte) {
	s := opts.Salt
	if s == nil {
		s = GenerateSalt(32)
	}
	dkLen := 32
	if opts.KeyLength != nil {
		dkLen = *opts.KeyLength
	}
	algo := opts.Algorithm
	if algo == "" {
		algo = "argon2id"
	}
	if algo == "pbkdf2" {
		iter := 100000
		if opts.Iterations != nil {
			iter = *opts.Iterations
		}
		key = pbkdf2Sync([]byte(passphrase), s, iter, dkLen)
	} else {
		mc := 32
		if opts.MemoryCost != nil {
			mc = *opts.MemoryCost
		}
		tc := 3
		if opts.TimeCost != nil {
			tc = *opts.TimeCost
		}
		key = argon2idLiteSync([]byte(passphrase), s, mc, tc, dkLen)
	}
	return key, s
}

// DeriveKeyForQuarkDash derive 64B (32B session + 32B MAC) for QuarkDash.
func DeriveKeyForQuarkDash(passphrase string, salt []byte, opts PassphraseOptions) (sessionKey, macKey []byte) {
	dkLen := 64
	algo := opts.Algorithm
	if algo == "" {
		algo = "argon2id"
	}
	var key []byte
	if algo == "pbkdf2" {
		iter := 100000
		if opts.Iterations != nil {
			iter = *opts.Iterations
		}
		key = pbkdf2Sync([]byte(passphrase), salt, iter, dkLen)
	} else {
		mc := 32
		if opts.MemoryCost != nil {
			mc = *opts.MemoryCost
		}
		tc := 3
		if opts.TimeCost != nil {
			tc = *opts.TimeCost
		}
		key = argon2idLiteSync([]byte(passphrase), salt, mc, tc, dkLen)
	}
	sessionKey = make([]byte, 32)
	macKey = make([]byte, 32)
	copy(sessionKey, key[:32])
	copy(macKey, key[32:64])
	return
}
