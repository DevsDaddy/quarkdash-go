/*
QuarkDash Implementation

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package quarkdash

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/DevsDaddy/quarkdash-go/cipher"
	"github.com/DevsDaddy/quarkdash-go/core"
	"github.com/DevsDaddy/quarkdash-go/rekey"
	"github.com/DevsDaddy/quarkdash-go/ringlwe"
)

// =============================================================================
// Protocol Errors
// =============================================================================

var (
	ErrSessionNotEstablished = errors.New("session not established")
	ErrSessionNotInitialized = errors.New("session not initialized")
	ErrMACVerificationFailed = errors.New("MAC verification failed")
	ErrTimestampOutOfWindow  = errors.New("timestamp out of window")
	ErrReplayDetected        = errors.New("replay detected")
	ErrRekeyCounterMismatch  = errors.New("rekey counter mismatch")
	ErrInvalidNonce          = errors.New("nonce must be 12 bytes")
	ErrInvalidCiphertext     = errors.New("invalid ciphertext")
)

// =============================================================================
// Re-export types from subpackets
// =============================================================================

// CipherType - type of symmetric cipher
type CipherType = cipher.CipherType

const (
	CipherChaCha20 = cipher.CipherChaCha20
	CipherGimli    = cipher.CipherGimli
)

// Cipher - a cipher interface
type Cipher = cipher.Cipher

// KDF interface
type KDF = core.KDF

// MAC authentication interface
type MAC = core.MAC

// RekeyPolicy key rotation policy
type RekeyPolicy = rekey.RekeyPolicy

var DefaultRekeyPolicy = rekey.DefaultRekeyPolicy

// NTTProtectionOptions - NTT security options
type NTTProtectionOptions = ringlwe.NTTProtectionOptions

var DefaultNTTProtection = ringlwe.DefaultNTTProtection

// KeyExchange - key exchange interface (KEM).
type KeyExchange interface {
	GenerateKeyPair() (pub, priv []byte)
	Encapsulate(pubKey []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(privKey, peerPubKey, ciphertext []byte) ([]byte, error)
}

// RekeyOptions - key rotation options.
type RekeyOptions struct {
	Policy    RekeyPolicy
	AutoRekey bool
	OnRekey   func(counter int)
}

// Options - basic QuarkDash configuration.
type Options struct {
	Cipher               CipherType
	KDF                  KDF
	MAC                  MAC
	KeyExchange          KeyExchange
	MaxPacketWindow      int
	TimestampToleranceMs int64
	Rekey                RekeyOptions
	UsePerMessageNonce   bool
}

// defaultOptions default QuarkDash Options
func defaultOptions() Options {
	return Options{
		Cipher:               CipherChaCha20,
		KDF:                  &core.QuarkDashKDF{},
		MAC:                  core.NewQuarkDashMAC(),
		KeyExchange:          ringlwe.NewRRLWE(),
		MaxPacketWindow:      1000,
		TimestampToleranceMs: 300000,
		Rekey: RekeyOptions{
			Policy:    DefaultRekeyPolicy,
			AutoRekey: false,
		},
		UsePerMessageNonce: true,
	}
}

// QuarkDash - general protocol class.
// Threadsafety (sync.Mutex), support per-message nonce, replay-security and rekey (key rotation).
type QuarkDash struct {
	mu     sync.Mutex
	config Options

	sessionKey []byte // 32B
	macKey     []byte // 32B
	cipher     Cipher // for static-nonce mode

	sendSeq         uint32
	receivedPackets map[uint32]struct{}

	myPublicKey   []byte
	myPrivateKey  []byte
	peerPublicKey []byte

	rekeyCounter      int
	bytesEncrypted    int
	messagesEncrypted int
	lastRekeyTime     time.Time
	rekeyPolicy       RekeyPolicy
}

// New create a new QuarkDash Instance with options.
func New(opts ...func(*Options)) *QuarkDash {
	cfg := defaultOptions()
	for _, fn := range opts {
		fn(&cfg)
	}
	return &QuarkDash{
		config:          cfg,
		receivedPackets: make(map[uint32]struct{}),
		rekeyPolicy:     cfg.Rekey.Policy,
		lastRekeyTime:   time.Now(),
	}
}

// Constructor options

func WithCipher(ct CipherType) func(*Options) { return func(o *Options) { o.Cipher = ct } }
func WithKDF(k KDF) func(*Options)            { return func(o *Options) { o.KDF = k } }
func WithMAC(m MAC) func(*Options)            { return func(o *Options) { o.MAC = m } }
func WithKeyExchange(kx KeyExchange) func(*Options) {
	return func(o *Options) { o.KeyExchange = kx }
}
func WithRekeyPolicy(p RekeyPolicy) func(*Options) { return func(o *Options) { o.Rekey.Policy = p } }
func WithUsePerMessageNonce(v bool) func(*Options) {
	return func(o *Options) { o.UsePerMessageNonce = v }
}
func WithMaxPacketWindow(n int) func(*Options) { return func(o *Options) { o.MaxPacketWindow = n } }
func WithTimestampToleranceMs(n int64) func(*Options) {
	return func(o *Options) { o.TimestampToleranceMs = n }
}

// GenerateKeyPair generates key pair (pub 1024B, private 512B).
func (qd *QuarkDash) GenerateKeyPair() []byte {
	pub, priv := qd.config.KeyExchange.GenerateKeyPair()
	qd.mu.Lock()
	qd.myPublicKey = pub
	qd.myPrivateKey = priv
	qd.mu.Unlock()
	return pub
}

// InitializeSession start a handshake.
// If isInitiator=true, return ciphertext to send to peer.
func (qd *QuarkDash) InitializeSession(peerPublicKey []byte, isInitiator bool) ([]byte, error) {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	qd.peerPublicKey = peerPublicKey
	if qd.myPublicKey == nil {
		pub, priv := qd.config.KeyExchange.GenerateKeyPair()
		qd.myPublicKey = pub
		qd.myPrivateKey = priv
	}
	if isInitiator {
		ct, ss, err := qd.config.KeyExchange.Encapsulate(peerPublicKey)
		if err != nil {
			return nil, err
		}
		qd.deriveSessionKeys(ss)
		core.SecureZero(ss)
		return ct, nil
	}
	return nil, nil
}

// FinalizeSession complete handshake on receiver side.
func (qd *QuarkDash) FinalizeSession(ciphertext []byte) error {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	if qd.myPrivateKey == nil || qd.peerPublicKey == nil {
		return ErrSessionNotInitialized
	}
	ss, err := qd.config.KeyExchange.Decapsulate(qd.myPrivateKey, qd.myPublicKey, ciphertext)
	if err != nil {
		return err
	}
	qd.deriveSessionKeys(ss)
	core.SecureZero(ss)
	return nil
}

// deriveSessionKeys derive sessionKey(32B) and macKey(32B) from sharedSecret using KDF.
// Use deterministic salt (32 zeros) and info="session-key" - compatible with TypeScript implementation
func (qd *QuarkDash) deriveSessionKeys(sharedSecret []byte) {
	info := core.TextToBytes("session-key")
	salt := make([]byte, 32)
	km := qd.config.KDF.Derive(sharedSecret, salt, info, 64)
	qd.sessionKey = make([]byte, 32)
	qd.macKey = make([]byte, 32)
	copy(qd.sessionKey, km[:32])
	copy(qd.macKey, km[32:64])
	qd.cipher = mustCipher(qd.config.Cipher, qd.sessionKey, make([]byte, 12))
	qd.rekeyCounter = 0
	qd.bytesEncrypted = 0
	qd.messagesEncrypted = 0
	qd.lastRekeyTime = time.Now()
	core.SecureZero(km)
}

// NeedsRekey checks, need key rotation or not using current policy.
func (qd *QuarkDash) NeedsRekey() bool {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	if qd.sessionKey == nil {
		return false
	}
	if qd.rekeyPolicy.AfterMessages > 0 && qd.messagesEncrypted >= qd.rekeyPolicy.AfterMessages {
		return true
	}
	if qd.rekeyPolicy.AfterBytes > 0 && qd.bytesEncrypted >= qd.rekeyPolicy.AfterBytes {
		return true
	}
	if qd.rekeyPolicy.IntervalMs > 0 && time.Since(qd.lastRekeyTime).Milliseconds() >= qd.rekeyPolicy.IntervalMs {
		return true
	}
	return false
}

// GetRekeyStats return key rotation static.
func (qd *QuarkDash) GetRekeyStats() (counter, bytesEnc, messagesEnc int, lastRekey time.Time, policy RekeyPolicy) {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	return qd.rekeyCounter, qd.bytesEncrypted, qd.messagesEncrypted, qd.lastRekeyTime, qd.rekeyPolicy
}

// SetRekeyPolicy update rotation policy.
func (qd *QuarkDash) SetRekeyPolicy(p RekeyPolicy) {
	qd.mu.Lock()
	qd.rekeyPolicy = p
	qd.mu.Unlock()
}

// GetRekeyCounter return key rotation counter.
func (qd *QuarkDash) GetRekeyCounter() int {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	return qd.rekeyCounter
}

// Rekey generates a key rotation token (encrypt payload with old session, and derive new keys).
func (qd *QuarkDash) Rekey() ([]byte, error) {
	qd.mu.Lock()
	salt := core.RandomBytes(32)
	payload := rekey.BuildRekeyPayload(salt, qd.rekeyCounter)
	qd.mu.Unlock()
	enc, err := qd.Encrypt(payload)
	if err != nil {
		return nil, err
	}
	if err := qd.doRekeyDerive(salt); err != nil {
		return nil, err
	}
	return enc, nil
}

// ApplyRekey apply key rotation token from peer (decrypt using old session, when derive).
func (qd *QuarkDash) ApplyRekey(token []byte) error {
	plain, err := qd.Decrypt(token)
	if err != nil {
		return err
	}
	salt, counter, err := rekey.ParseRekeyPayload(plain)
	core.SecureZero(plain)
	if err != nil {
		return err
	}
	qd.mu.Lock()
	expected := qd.rekeyCounter
	qd.mu.Unlock()
	if counter != expected {
		return ErrRekeyCounterMismatch
	}
	return qd.doRekeyDerive(salt)
}

func (qd *QuarkDash) doRekeyDerive(salt []byte) error {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	if qd.sessionKey == nil || qd.macKey == nil {
		return ErrSessionNotEstablished
	}
	mat := rekey.DeriveRekeyMaterial(qd.config.KDF, qd.sessionKey, qd.macKey, salt, qd.rekeyCounter, "")
	qd.reinitSession(mat)
	core.SecureZero(mat)
	return nil
}

func (qd *QuarkDash) reinitSession(mat []byte) {
	newSess := make([]byte, 32)
	newMac := make([]byte, 32)
	copy(newSess, mat[:32])
	copy(newMac, mat[32:64])
	core.SecureZero(qd.sessionKey)
	core.SecureZero(qd.macKey)
	qd.sessionKey = newSess
	qd.macKey = newMac
	qd.cipher = mustCipher(qd.config.Cipher, qd.sessionKey, make([]byte, 12))
	qd.rekeyCounter++
	qd.bytesEncrypted = 0
	qd.messagesEncrypted = 0
	qd.lastRekeyTime = time.Now()
	if qd.config.Rekey.OnRekey != nil {
		qd.config.Rekey.OnRekey(qd.rekeyCounter)
	}
}

// Encrypt encrypt data: [12B metadata | ciphertext | 32B MAC].
func (qd *QuarkDash) Encrypt(plaintext []byte) ([]byte, error) {
	qd.mu.Lock()
	if qd.sessionKey == nil || qd.macKey == nil {
		qd.mu.Unlock()
		return nil, ErrSessionNotEstablished
	}
	metadata := qd.buildMetadataLocked()
	ciph := qd.cipherForNonceLocked(metadata)
	qd.mu.Unlock()

	var encrypted []byte
	switch c := ciph.(type) {
	case *cipher.QuarkDashChaCha:
		encrypted = c.Encrypt(plaintext)
	case *cipher.QuarkDashGimli:
		encrypted = c.Encrypt(plaintext)
	default:
		encrypted = ciph.Encrypt(plaintext)
	}
	// MAC по metadata||encrypted
	var mac []byte
	if qdm, ok := qd.config.MAC.(*core.QuarkDashMAC); ok {
		mac = qdm.SignTwo(metadata, encrypted, qd.macKey)
	} else {
		mac = qd.config.MAC.SignTwo(metadata, encrypted, qd.macKey)
	}
	result := make([]byte, len(metadata)+len(encrypted)+len(mac))
	copy(result, metadata)
	copy(result[len(metadata):], encrypted)
	copy(result[len(metadata)+len(encrypted):], mac)

	qd.mu.Lock()
	qd.bytesEncrypted += len(plaintext)
	qd.messagesEncrypted++
	qd.mu.Unlock()
	return result, nil
}

// Decrypt decrypt data and check MAC with reply-security.
func (qd *QuarkDash) Decrypt(ciphertext []byte) ([]byte, error) {
	qd.mu.Lock()
	if qd.sessionKey == nil || qd.macKey == nil {
		qd.mu.Unlock()
		return nil, ErrSessionNotEstablished
	}
	qd.mu.Unlock()

	if len(ciphertext) < 44 {
		return nil, ErrInvalidCiphertext
	}
	metadata := ciphertext[:12]
	encrypted := ciphertext[12 : len(ciphertext)-32]
	mac := ciphertext[len(ciphertext)-32:]

	var valid bool
	if qdm, ok := qd.config.MAC.(*core.QuarkDashMAC); ok {
		valid = qdm.VerifyTwo(metadata, encrypted, qd.macKey, mac)
		if !valid {
			exp := qdm.SignTwo(metadata, encrypted, qd.macKey)
			valid = core.ConstantTimeEqual(exp, mac)
		}
	} else {
		full := core.ConcatBytes(metadata, encrypted)
		valid = qd.config.MAC.Verify(full, qd.macKey, mac)
	}
	if !valid {
		return nil, ErrMACVerificationFailed
	}
	if err := qd.checkMetadata(metadata); err != nil {
		return nil, err
	}
	qd.mu.Lock()
	ciph := qd.cipherForNonceLocked(metadata)
	qd.mu.Unlock()
	switch c := ciph.(type) {
	case *cipher.QuarkDashChaCha:
		return c.Decrypt(encrypted), nil
	case *cipher.QuarkDashGimli:
		return c.Decrypt(encrypted), nil
	default:
		return ciph.Decrypt(encrypted), nil
	}
}

// Dispose cleanup keys in memory.
func (qd *QuarkDash) Dispose() {
	qd.mu.Lock()
	defer qd.mu.Unlock()
	if qd.sessionKey != nil {
		core.SecureZero(qd.sessionKey)
	}
	if qd.macKey != nil {
		core.SecureZero(qd.macKey)
	}
	qd.sessionKey = nil
	qd.macKey = nil
	qd.cipher = nil
	qd.receivedPackets = make(map[uint32]struct{})
}

func (qd *QuarkDash) cipherForNonceLocked(nonce []byte) Cipher {
	if !qd.config.UsePerMessageNonce {
		return qd.cipher
	}
	if len(nonce) != 12 {
		panic(ErrInvalidNonce)
	}
	return mustCipher(qd.config.Cipher, qd.sessionKey, nonce)
}

// buildMetadataLocked collect 12B of metadata: 8B timestamp LE + 4B seq LE.
func (qd *QuarkDash) buildMetadataLocked() []byte {
	meta := make([]byte, 12)
	ts := uint64(time.Now().UnixMilli())
	binary.LittleEndian.PutUint64(meta[0:8], ts)
	binary.LittleEndian.PutUint32(meta[8:12], qd.sendSeq)
	qd.sendSeq++
	return meta
}

// checkMetadata check timestamp and replay (sliding window).
func (qd *QuarkDash) checkMetadata(metadata []byte) error {
	ts := binary.LittleEndian.Uint64(metadata[0:8])
	now := uint64(time.Now().UnixMilli())
	diff := int64(now) - int64(ts)
	if diff < 0 {
		diff = -diff
	}
	qd.mu.Lock()
	tol := qd.config.TimestampToleranceMs
	seq := binary.LittleEndian.Uint32(metadata[8:12])
	if _, exists := qd.receivedPackets[seq]; exists {
		qd.mu.Unlock()
		return ErrReplayDetected
	}
	if diff > tol {
		qd.mu.Unlock()
		return ErrTimestampOutOfWindow
	}
	qd.receivedPackets[seq] = struct{}{}
	if len(qd.receivedPackets) > qd.config.MaxPacketWindow {
		var oldest uint32 = ^uint32(0)
		for k := range qd.receivedPackets {
			if k < oldest {
				oldest = k
			}
		}
		delete(qd.receivedPackets, oldest)
	}
	qd.mu.Unlock()
	return nil
}

// GetSessionKey / GetMacKey - for tests/debugging.
func (qd *QuarkDash) GetSessionKey() []byte { return qd.sessionKey }
func (qd *QuarkDash) GetMacKey() []byte     { return qd.macKey }

// mustCipher - helper, panic with invalid parameters.
func mustCipher(ct CipherType, key, nonce []byte) Cipher {
	c, err := cipher.NewCipher(ct, key, nonce)
	if err != nil {
		panic(err)
	}
	return c
}
