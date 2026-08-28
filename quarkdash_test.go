/*
QuarkDash Test

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
	"sync"
	"testing"
)

// TestEmptyData test empty data
func TestEmptyData(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, err := alice.InitializeSession(bPub, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.InitializeSession(aPub, false); err != nil {
		t.Fatal(err)
	}
	if err := bob.FinalizeSession(ct); err != nil {
		t.Fatal(err)
	}
	plain := []byte{}
	enc, err := alice.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := bob.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != 0 {
		t.Fatalf("expected empty, got %d", len(dec))
	}
}

// TestSimpleUTF8Gimli test simple UTF8 data with Gimli cipher
func TestSimpleUTF8Gimli(t *testing.T) {
	alice := New(WithCipher(CipherGimli))
	bob := New(WithCipher(CipherGimli))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := TextToBytes("Hello QuarkDash 🔒!")
	enc, _ := alice.Encrypt(plain)
	dec, _ := bob.Decrypt(enc)
	if BytesToText(dec) != "Hello QuarkDash 🔒!" {
		t.Fatalf("mismatch %q", BytesToText(dec))
	}
	enc3, _ := bob.Encrypt(plain)
	dec3, _ := alice.Decrypt(enc3)
	if BytesToText(dec3) != "Hello QuarkDash 🔒!" {
		t.Fatalf("reverse mismatch")
	}
}

// TestLargeData64KB test large data (64kb)
func TestLargeData64KB(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := RandomBytes(64 * 1024)
	enc, _ := alice.Encrypt(plain)
	dec, _ := bob.Decrypt(enc)
	if !bytes.Equal(dec, plain) {
		t.Fatal("large data mismatch")
	}
}

// TestReplayAttack test reply attack security
func TestReplayAttack(t *testing.T) {
	alice := New()
	bob := New()
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := TextToBytes("test")
	enc, _ := alice.Encrypt(plain)
	if _, err := bob.Decrypt(enc); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Decrypt(enc); err == nil {
		t.Fatal("expected replay error")
	} else if err != ErrReplayDetected {
		t.Logf("got %v", err)
	}
}

// TestMACCorruption test MAC validation
func TestMACCorruption(t *testing.T) {
	alice := New()
	bob := New()
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := TextToBytes("test")
	enc, _ := alice.Encrypt(plain)
	enc[len(enc)-1] ^= 0xff
	if _, err := bob.Decrypt(enc); err != ErrMACVerificationFailed {
		t.Fatalf("expected MAC fail got %v", err)
	}
}

// TestConcurrentSessions test concurrent sessions in QuarkDash
func TestConcurrentSessions(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			a := New(WithCipher(CipherChaCha20))
			b := New(WithCipher(CipherChaCha20))
			aPub := a.GenerateKeyPair()
			bPub := b.GenerateKeyPair()
			ct, _ := a.InitializeSession(bPub, true)
			_, _ = b.InitializeSession(aPub, false)
			b.FinalizeSession(ct)
			msg := TextToBytes("msg" + itoa(idx))
			enc, _ := a.Encrypt(msg)
			dec, _ := b.Decrypt(enc)
			if BytesToText(dec) != "msg"+itoa(idx) {
				t.Errorf("concurrent mismatch")
			}
		}(i)
	}
	wg.Wait()
}

// TestSyncAPI test sync api
func TestSyncAPI(t *testing.T) {
	alice := New(WithCipher(CipherChaCha20))
	bob := New(WithCipher(CipherChaCha20))
	aPub := alice.GenerateKeyPair()
	bPub := bob.GenerateKeyPair()
	ct, _ := alice.InitializeSession(bPub, true)
	_, _ = bob.InitializeSession(aPub, false)
	bob.FinalizeSession(ct)
	plain := TextToBytes("sync test")
	enc, _ := alice.Encrypt(plain)
	dec, _ := bob.Decrypt(enc)
	if BytesToText(dec) != "sync test" {
		t.Fatal("sync api fail")
	}
}
