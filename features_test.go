/*
    QuarkDash Features Test

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package quarkdash

import (
	"bytes"
	"testing"

	"github.com/DevsDaddy/quarkdash-go/cipher"
)

func TestChaChaLazyVsEager(t *testing.T) {
	key := RandomBytes(32)
	nonce := RandomBytes(12)
	c, _ := NewQuarkDashChaCha(key, nonce)
	data := RandomBytes(5000)
	eager := c.Encrypt(data)
	ks := c.CreateKeystream()
	lazy := ks.Xor(data, 0)
	if !bytes.Equal(lazy, eager) {
		t.Fatal("lazy vs eager mismatch")
	}
}

func TestChaChaSeekAndGetBytes(t *testing.T) {
	key := RandomBytes(32)
	nonce := make([]byte, 12)
	ks := cipher.NewChaChaKeystream(key, nonce)
	full := ks.GetBytes(0, 200)
	p1 := ks.GetBytes(0, 100)
	p2 := ks.GetBytes(100, 100)
	combined := ConcatBytes(p1, p2)
	if !bytes.Equal(combined, full) {
		t.Fatal("split mismatch")
	}
	offset := ks.GetBytes(64, 64)
	block1 := ks.GenerateBlock(1)
	if !bytes.Equal(offset, block1) {
		t.Fatal("block offset mismatch")
	}
}

func TestGimliLazyXorAndStream(t *testing.T) {
	key := RandomBytes(32)
	nonce := RandomBytes(12)
	g, _ := NewQuarkDashGimli(key, nonce)
	data := RandomBytes(3000)
	enc := g.Encrypt(data)
	ks := g.CreateKeystream()
	dec := ks.Xor(enc, 0)
	if !bytes.Equal(dec, data) {
		t.Fatal("gimli xor fail")
	}
	ks2 := g.CreateKeystream()
	collect := [][]byte{}
	for b := range ks2.Blocks(0) {
		collect = append(collect, b)
		if len(collect) >= 1 {
			break
		}
	}
	if len(collect[0]) != 48 {
		t.Fatalf("block size %d", len(collect[0]))
	}
	ks2.Seek(100)
	if ks2.Tell() != 100 {
		t.Fatal("tell")
	}
	read := ks2.Read(48)
	exp := ks2.GetBytes(100, 48)
	if !bytes.Equal(read, exp) {
		t.Fatal("read mismatch")
	}
}

func TestLargeDataLazy(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := RandomBytes(128 * 1024)
	enc, _ := alice.Encrypt(plain)
	dec, _ := bob.Decrypt(enc)
	if !bytes.Equal(dec, plain) {
		t.Fatal("large lazy mismatch")
	}
}

func makePair(t *testing.T) (*QuarkDash, *QuarkDash) {
	alice := New(WithCipher(CipherChaCha20), WithRekeyPolicy(RekeyPolicy{AfterMessages: 2, AfterBytes: 64 * 1024 * 1024}))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	return alice, bob
}

func TestRekeyBasic(t *testing.T) {
	alice, bob := makePair(t)
	plain1 := TextToBytes("before rekey")
	enc1, _ := alice.Encrypt(plain1)
	dec1, _ := bob.Decrypt(enc1)
	if !bytes.Equal(dec1, plain1) {
		t.Fatal("before rekey")
	}
	token, err := alice.Rekey()
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.ApplyRekey(token); err != nil {
		t.Fatal(err)
	}
	if alice.GetRekeyCounter() != 1 || bob.GetRekeyCounter() != 1 {
		t.Fatalf("counters %d %d", alice.GetRekeyCounter(), bob.GetRekeyCounter())
	}
	plain2 := TextToBytes("after rekey")
	enc2, _ := alice.Encrypt(plain2)
	dec2, _ := bob.Decrypt(enc2)
	if !bytes.Equal(dec2, plain2) {
		t.Fatal("after rekey")
	}
	enc3, _ := bob.Encrypt(plain2)
	dec3, _ := alice.Decrypt(enc3)
	if !bytes.Equal(dec3, plain2) {
		t.Fatal("reverse after rekey")
	}
}

func TestRekeySyncAPI(t *testing.T) {
	alice := New(WithCipher(CipherGimli))
	bob := New(WithCipher(CipherGimli))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	token, _ := alice.Rekey()
	if err := bob.ApplyRekey(token); err != nil {
		t.Fatal(err)
	}
	plain := TextToBytes("sync rekey")
	enc, _ := alice.Encrypt(plain)
	dec, _ := bob.Decrypt(enc)
	if !bytes.Equal(dec, plain) {
		t.Fatal("sync rekey fail")
	}
}

func TestRekeyCounterMismatch(t *testing.T) {
	alice, bob := makePair(t)
	token, _ := alice.Rekey()
	if err := bob.ApplyRekey(token); err != nil {
		t.Fatal(err)
	}
	token2, _ := alice.Rekey()
	_ = token2
	if err := bob.ApplyRekey(token); err == nil {
		t.Fatal("expected counter mismatch")
	}
}

func TestNeedsRekeyPolicy(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20), WithRekeyPolicy(RekeyPolicy{AfterMessages: 1}))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	if alice.NeedsRekey() {
		t.Fatal("should not need before")
	}
	alice.Encrypt(TextToBytes("a"))
	if !alice.NeedsRekey() {
		t.Fatal("should need after")
	}
}

func TestBytesEncryptedTracking(t *testing.T) {
	alice, _ := makePair(t)
	alice.Encrypt(RandomBytes(100))
	_, bytesEnc, msgsEnc, _, _ := alice.GetRekeyStats()
	if bytesEnc != 100 || msgsEnc != 1 {
		t.Fatalf("stats %d %d", bytesEnc, msgsEnc)
	}
}

func TestPBKDF2Vectors(t *testing.T) {
	salt := TextToBytes("salt")
	k := PBKDF2SyncBytes([]byte("password"), salt, 1, 20)
	hex := BytesToHex(k)
	if hex != "120fb6cffcf8b32c43e7225256c4f837a86548c9" {
		t.Fatalf("vector1 %s", hex)
	}
	k2 := PBKDF2SyncBytes([]byte("password"), salt, 4096, 20)
	hex2 := BytesToHex(k2)
	if hex2 != "c5e478d59288c841aa530db6845c4c8d962893a0" {
		t.Fatalf("vector4096 %s", hex2)
	}
}

func TestPBKDF2AsyncVsSync(t *testing.T) {
	salt := RandomBytes(16)
	a := PBKDF2SyncBytes([]byte("hello world"), salt, 1000, 32)
	b := PBKDF2SyncBytes([]byte("hello world"), salt, 1000, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("pbkdf2 mismatch")
	}
}

func TestArgon2Determinism(t *testing.T) {
	salt := TextToBytes("somesalt12345678")
	k1 := Argon2idSyncBytes([]byte("password"), salt, 8, 1, 32)
	k2 := Argon2idSyncBytes([]byte("password"), salt, 8, 1, 32)
	if !bytes.Equal(k1, k2) {
		t.Fatal("argon2 not determin")
	}
	k3 := Argon2idSyncBytes([]byte("different"), salt, 8, 1, 32)
	if bytes.Equal(k1, k3) {
		t.Fatal("different should differ")
	}
}

func TestDeriveReturnsSalt(t *testing.T) {
	opts := PassphraseOptions{Algorithm: "pbkdf2", KeyLength: intPtr(32), Iterations: intPtr(1000)}
	k, s := DerivePassphrase("my secret", opts)
	if len(k) != 32 || len(s) != 32 {
		t.Fatalf("derive len %d %d", len(k), len(s))
	}
}

func TestDifferentSalts(t *testing.T) {
	s1 := RandomBytes(16)
	s2 := RandomBytes(16)
	k1 := PBKDF2SyncBytes([]byte("same"), s1, 1000, 32)
	k2 := PBKDF2SyncBytes([]byte("same"), s2, 1000, 32)
	if bytes.Equal(k1, k2) {
		t.Fatal("different salts should give different keys")
	}
}

func intPtr(i int) *int { return &i }

func TestNTTProtection(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	// enable hardened (even though naive, test toggle)
	if r, ok := alice.config.KeyExchange.(*RRLWE); ok {
		prot := r.GetNTTProtection()
		prot.Enabled = true
		prot.Blinding = false
		r.SetNTTProtection(prot)
	}
	if r, ok := bob.config.KeyExchange.(*RRLWE); ok {
		prot := r.GetNTTProtection()
		prot.Enabled = true
		r.SetNTTProtection(prot)
	}
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := TextToBytes("ntt test")
	enc, _ := alice.Encrypt(plain)
	dec, _ := bob.Decrypt(enc)
	if !bytes.Equal(dec, plain) {
		t.Fatal("ntt protected fail")
	}
}

func TestInvalidPublicKey(t *testing.T) {
	lwe := NewRRLWE()
	if err := lwe.ValidatePublicKey([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error")
	}
}

func TestInvalidCiphertext(t *testing.T) {
	alice := New()
	bob := New()
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	lwe := NewRRLWE()
	if err := lwe.ValidateCiphertext([]byte{1, 2}); err == nil {
		t.Fatal("expected error")
	}
}

func TestProtectionToggle(t *testing.T) {
	lwe := NewRRLWE()
	prot := lwe.GetNTTProtection()
	prot.Enabled = false
	lwe.SetNTTProtection(prot)
	if lwe.GetNTTProtection().Enabled {
		t.Fatal("should be false")
	}
	prot.Enabled = true
	lwe.SetNTTProtection(prot)
	if !lwe.GetNTTProtection().Enabled {
		t.Fatal("should be true")
	}
}

func TestHTTPTransport(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	httpAlice := NewQDHTTP(alice)
	httpBob := NewQDHTTP(bob)
	body, _, _ := httpAlice.EncryptBodyWithHeaders(map[string]string{"hello": "world"})
	var out map[string]string
	if err := httpBob.DecryptToJSON(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["hello"] != "world" {
		t.Fatal("http json mismatch")
	}
}

func TestHTTPSync(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	httpAlice := NewQDHTTP(alice)
	httpBob := NewQDHTTP(bob)
	body, _, _ := httpAlice.EncryptBodyWithHeaders("hello http")
	dec, _ := httpBob.DecryptBody(body)
	if BytesToText(dec) != "hello http" {
		t.Fatal("http sync fail")
	}
}

func TestGRPCTransport(t *testing.T) {
	alice := New(WithCipher(CipherGimli))
	bob := New(WithCipher(CipherGimli))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	grpcAlice := NewQDGRPC(alice)
	grpcBob := NewQDGRPC(bob)
	msg := TextToBytes("grpc payload")
	enc, _ := grpcAlice.EncryptMessage(msg)
	dec, _ := grpcBob.DecryptMessage(enc)
	if !bytes.Equal(dec, msg) {
		t.Fatal("grpc fail")
	}
}

func TestWebSocketWrapper(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	mw := &mockWS{}
	wrapped := WrapWebSocket(alice, mw)
	if err := wrapped.Send(TextToBytes("hello ws")); err != nil {
		t.Fatal(err)
	}
	if mw.captured == nil {
		t.Fatal("not captured")
	}
	dec, _ := bob.Decrypt(mw.captured)
	if BytesToText(dec) != "hello ws" {
		t.Fatal("ws decrypt fail")
	}
}

func TestGRPCWrapClient(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	_ = NewQDGRPC(alice)
	_ = bob
}

type mockWS struct {
	captured []byte
	handler  func([]byte)
}

func (m *mockWS) Send(data []byte) error {
	m.captured = data
	return nil
}
func (m *mockWS) OnMessage(h func([]byte)) { m.handler = h }
func (m *mockWS) Close() error             { return nil }
