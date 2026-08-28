/*
    QuarkDash Module

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package quarkdash

import (
	"github.com/DevsDaddy/quarkdash-go/cipher"
	"github.com/DevsDaddy/quarkdash-go/core"
	"github.com/DevsDaddy/quarkdash-go/hash"
	"github.com/DevsDaddy/quarkdash-go/passphrase"
	"github.com/DevsDaddy/quarkdash-go/ringlwe"
	"github.com/DevsDaddy/quarkdash-go/transport"
)

// =============================================================================
// Re-export core utils
// =============================================================================
func TextToBytes(s string) []byte { return core.TextToBytes(s) }
func BytesToText(b []byte) string { return core.BytesToText(b) }
func BytesToHex(b []byte) string { return core.BytesToHex(b) }
func RandomBytes(n int) []byte { return core.RandomBytes(n) }
func ConcatBytes(arrays ...[]byte) []byte { return core.ConcatBytes(arrays...) }
func SecureZeroBytes(b []byte) { core.SecureZero(b) }

// =============================================================================
// Hashes
// =============================================================================
func Shake256Hash(data []byte, outLen int) []byte { return hash.Shake256(data, outLen) }
func SHA256Hash(data []byte) []byte { return hash.SHA256Hash(data) }
func SHA512Hash(data []byte) []byte { return hash.SHA512Hash(data) }

// =============================================================================
// Ciphers (cipher) - re-export
// =============================================================================
type QuarkDashChaCha = cipher.QuarkDashChaCha
type QuarkDashGimli = cipher.QuarkDashGimli
type ChaChaKeystream = cipher.ChaChaKeystream
type GimliKeystream = cipher.GimliKeystream
func NewQuarkDashChaCha(key, nonce []byte) (*QuarkDashChaCha, error) { return cipher.NewQuarkDashChaCha(key, nonce)}
func NewQuarkDashGimli(key, nonce []byte) (*QuarkDashGimli, error) { return cipher.NewQuarkDashGimli(key, nonce) }

// =============================================================================
// KDF / MAC
// =============================================================================
type QuarkDashKDF = core.QuarkDashKDF
type QuarkDashMAC = core.QuarkDashMAC
func NewQuarkDashKDF() *QuarkDashKDF { return &QuarkDashKDF{} }
func NewQuarkDashMAC() *QuarkDashMAC { return core.NewQuarkDashMAC() }

// =============================================================================
// Ring LWE
// =============================================================================
type BaseRingLWE = ringlwe.BaseRingLWE

type RingLWE = ringlwe.RingLWE
type RRLWE = ringlwe.RRLWE

func NewRingLWE() *RingLWE { return ringlwe.NewRingLWE() }
func NewRRLWE() *RRLWE     { return ringlwe.NewRRLWE() }

type QuarkDashRLWE = RingLWE
type QuarkDashRRLWE = RRLWE

func NewQuarkDashRLWE() *RingLWE { return NewRingLWE() }
func NewQuarkDashRRLWE() *RRLWE  { return NewRRLWE() }

// =============================================================================
// Passphrase
// =============================================================================
type PassphraseOptions = passphrase.PassphraseOptions

func GenerateSalt(length int) []byte { return passphrase.GenerateSalt(length) }
func PBKDF2Sync(pass string, salt []byte, iter, dkLen int) []byte { return passphrase.PBKDF2Sync(pass, salt, iter, dkLen) }
func PBKDF2SyncBytes(pass, salt []byte, iter, dkLen int) []byte { return passphrase.PBKDF2SyncBytes(pass, salt, iter, dkLen) }
func Argon2idSync(pass string, salt []byte, mc, tc, dkLen int) []byte { return passphrase.Argon2idSync(pass, salt, mc, tc, dkLen) }
func Argon2idSyncBytes(pass, salt []byte, mc, tc, dkLen int) []byte { return passphrase.Argon2idSyncBytes(pass, salt, mc, tc, dkLen) }
func DerivePassphrase(pass string, opts PassphraseOptions) (key, salt []byte) { return passphrase.DerivePassphrase(pass, opts) }
func DeriveKeyForQuarkDash(pass string, salt []byte, opts PassphraseOptions) (sess, mac []byte) { return passphrase.DeriveKeyForQuarkDash(pass, salt, opts) }

// =============================================================================
// Transport wrappers - Lightweight transport
// =============================================================================
type QDHTTP = transport.QDHTTP
type QDHTTPOptions = transport.QDHTTPOptions
type QDGRPC = transport.QDGRPC
type GrpcCall = transport.GrpcCall
type QDWebSocket = transport.QDWebSocket
type WSLike = transport.WSLike

func NewQDHTTP(enc Encryptor, opts ...QDHTTPOptions) *QDHTTP { return transport.NewQDHTTP(enc, opts...) }
func NewQDGRPC(enc Encryptor, metaKey ...string) *QDGRPC { return transport.NewQDGRPC(enc, metaKey...) }
func NewQDWebSocket(enc Encryptor, ws WSLike) *QDWebSocket { return transport.NewQDWebSocket(enc, ws) }
func WrapWebSocket(enc Encryptor, ws WSLike) *QDWebSocket { return transport.WrapWebSocket(enc, ws) }

// Encryptor - alias for transport.Encryptor (for external usage)
type Encryptor = transport.Encryptor

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
