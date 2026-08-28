/*
QuarkDash Key Benchmark

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package quarkdash

import "testing"

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		r := NewRRLWE()
		r.GenerateKeyPair()
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	r := NewRRLWE()
	pub, _ := r.GenerateKeyPair()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Encapsulate(pub)
	}
}

func BenchmarkEncrypt1KB(b *testing.B) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := RandomBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alice.Encrypt(plain)
	}
}

func BenchmarkDecrypt1KB(b *testing.B) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := RandomBytes(1024)
	enc, _ := alice.Encrypt(plain)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bob.Decrypt(enc)
	}
}

func BenchmarkChaCha(b *testing.B) {
	key := RandomBytes(32)
	nonce := RandomBytes(12)
	c, _ := NewQuarkDashChaCha(key, nonce)
	data := RandomBytes(1024 * 1024)
	b.SetBytes(1024 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(data)
	}
}

func BenchmarkGimli(b *testing.B) {
	key := RandomBytes(32)
	nonce := RandomBytes(12)
	c, _ := NewQuarkDashGimli(key, nonce)
	data := RandomBytes(1024 * 1024)
	b.SetBytes(1024 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(data)
	}
}

func BenchmarkEncrypt1MB(b *testing.B) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := RandomBytes(1024 * 1024)
	b.SetBytes(1024 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alice.Encrypt(plain)
	}
}

func BenchmarkDecrypt1MB(b *testing.B) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := RandomBytes(1024 * 1024)
	enc, _ := alice.Encrypt(plain)
	b.SetBytes(1024 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bob.Decrypt(enc)
	}
}
