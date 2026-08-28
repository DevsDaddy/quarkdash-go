# Welcome to QuarkDash Go 🔒 Repository
### Current version: 1.2.1 LTS (August 2026)
![QuarkDash Crypto Protocol](https://github.com/DevsDaddy/quarkdash/raw/main/img/cover.png)

**QuarkDash Go** - pure Golang implementation of hybrid post-quantum algorythm. It provides provides post-quantum security, high performance, and attack resistance.

> **This is an official protocol port from [QuarkDash Typescript Implementation](https://github.com/DevsDaddy/quarkdash) v1.2.0 (clean Go, minimum of dependencies).

[![Go 1.23](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#tests)

> Have a questions? <a href="mailto:ilya@neurosell.top">Contact me</a>

---

[Paper](https://github.com/DevsDaddy/quarkdash/blob/main/whitepaper.pdf) | [About](#about-quarkdash-crypto) | [Get Started](#-installation) | [TypeScript Version](https://github.com/devsdaddy/quarkdash)

---

## About QuarkDash Crypto
**QuarkDash Crypto** - It is a hybrid cryptographic protocol that provides post-quantum security, high performance, and attack resistance.
This library can be used as shared solution for your Go applications / server. Written on **pure Go (carefully ported from TS)**. **Dependency-free**.

> Algorithm Scheme [can be found here](https://app.holst.so/share/b/7ae942f8-8a40-42c9-9991-3b624f147da8)

**[Read full paper](https://github.com/DevsDaddy/quarkdash/blob/main/whitepaper.pdf)**

---

### ❓ Why QuarkDash Crypto?<br/>
🔹 **Lightweight library** with zero dependencies;<br/>
🔹 **Powerful crypto** algorithm written in **Go**;<br/>
🔹 **Extremely** fast (great for realtime and IoT applications);<br/>
🔹 **Production ready** with benchmarks;

### 🔒 General Components
- **Asymmetric key exchange**: Ring-LWE (N=256, Q=7681, ROOT=5685) / R-Ring-LWE (Q=12289, ROOT=8340);
- **Symmetric encryption**: ChaCha20 (RFC 7539, 64B block) or lightweight Gimli (48B block) with **lazy keystream generation**;
- **Key Derivation Function (KDF)**: SHAKE256 + HKDF-style expand;
- **Message Authentication Code (MAC)**: SHAKE256(key‖data) 32B, constant-time verify, reusable buffer;
- **Hash**: SHA-256 / SHA-512  and SHAKE-256;
- **Replay protection**: timestamp (LE64) + sequence number (LE32) + sliding window;
- **Passphrase KDF**: PBKDF2-HMAC-SHA256 / Argon2id-lite;
- **Transports**: WebSocket / HTTP / gRPC wrappers.
- **Key rotation**: by bytes / messages / time.

---

## 📁 Project structure

```
quarkdash-go/
├── go.mod                 # module github.com/DevsDaddy/quarkdash-go (Go 1.23)
├── quarkdash.go           # QuarkDash protocol core (handshake, Encrypt/Decrypt, rekey)
├── api.go                 # public facade - reexport for TS API compatible
├── cipher/                # symmetric ciphers with lazy keystream
│   ├── cipher.go          # CipherType, NewCipher
│   ├── keystream.go       # LazyKeystream (LRU 64 blocks, Seek/Tell/XorInto)
│   ├── chacha.go          # ChaCha20 (20 rounds, 64B block)
│   └── gimli.go           # Gimli (24 rounds, 48B block)
├── hash/                  # Hashes
│   ├── shake.go           # SHAKE256 (Keccak-f[1600], 24 rounds, rate 136)
│   └── sha.go             # SHA-256 / SHA-512 (stdlib, wrappers)
├── core/                  # Basic primitives
│   ├── utils.go           # Core helpers: ConcatBytes, RandomBytes, SecureZero, ConstantTimeEqual, LE helpers
│   ├── kdf.go             # QuarkDashKDF (SHAKE256, HKDF-like)
│   └── mac.go             # QuarkDashMAC (SHAKE256, reusable buffer)
├── ringlwe/               # Postquantum exchange (KEM)
│   └── ringlwe.go         # BaseRingLWE, RingLWE, RRLWE, NTT, polynomes, security
├── rekey/                 # Key rotation
│   └── rekey.go           # RekeyPolicy, Build/ParseRekeyPayload, DeriveRekeyMaterial
├── passphrase/            # KDF from password
│   └── passphrase.go      # PBKDF2, Argon2id-lite, DerivePassphrase
├── transport/             # Transport wrappers
│   ├── http.go            # QDHTTP (EncryptBody, Middleware, EncryptRequest)
│   ├── grpc.go            # QDGRPC (EncryptMessage, ServerInterceptor, WrapClient)
│   └── websocket.go       # QDWebSocket (Send/SendJSON, OnDecrypted)
├── quarkdash_test.go      # Main algorythm tests
├── features_test.go       # Main features tests
├── bench_test.go          # Benchmarks
└── README.md
```

If you need a **full description of algorythm** - **[Welcome to our WIKI](https://github.com/DevsDaddy/quarkdash/wiki)**

---

## 🚀 Installation

```bash
go get github.com/DevsDaddy/quarkdash-go
```

Requires **Go 1.23+**. Without `cgo`, without external dependencies (only `stdlib`).

---

## ⚡ Quick Start

```go
import qd "github.com/DevsDaddy/quarkdash-go"

alice := qd.New(qd.WithCipher(qd.CipherChaCha20))
bob   := qd.New(qd.WithCipher(qd.CipherChaCha20))

aPub := alice.GenerateKeyPair() // 1024B
bPub := bob.GenerateKeyPair()

ct, _ := alice.InitializeSession(bPub, true)  // Alice — initiator
_, _   = bob.InitializeSession(aPub, false)
_      = bob.FinalizeSession(ct)              // Bob — receiver

plain := qd.TextToBytes("Hello QuarkDash 🔒!")
enc, _ := alice.Encrypt(plain) // [12B meta | ciphertext | 32B MAC]
dec, _ := bob.Decrypt(enc)
fmt.Println(qd.BytesToText(dec)) // Hello QuarkDash 🔒!
```

### Gimli (IoT)

```go
alice := qd.New(qd.WithCipher(qd.CipherGimli))
bob   := qd.New(qd.WithCipher(qd.CipherGimli))
// same handshake
```

### Lazy keystream (zero-copy, seek)

```go
key, nonce := qd.RandomBytes(32), qd.RandomBytes(12)
chacha, _ := qd.NewQuarkDashChaCha(key, nonce)
ks := chacha.CreateKeystream()          // ChaChaKeystream (64B block)

chunk := ks.GetBytes(1024, 512)         // custom offset without recompute of all stream
enc   := ks.Xor(plain, 1024)            // XOR with offset
ks.Seek(0)
block := ks.GenerateBlock(1)            // 64B block #1

// Gimli works same - but with 48B block
gimli, _ := qd.NewQuarkDashGimli(key, nonce)
gks := gimli.CreateKeystream()
```

### Key rotation

```go
alice := qd.New(qd.WithCipher(qd.CipherChaCha20), qd.WithRekeyPolicy(qd.RekeyPolicy{AfterBytes: 64*1024*1024, AfterMessages: 10000}))
bob := qd.New(qd.WithCipher(qd.CipherChaCha20))
// ... handshake ...
token, _ := alice.Rekey() // encrypt payload with old session, when derive new keys
_ = bob.ApplyRekey(token)  // decrypt using old session, when derive

if alice.NeedsRekey() { token, _ := alice.Rekey(); bob.ApplyRekey(token) }
cnt, bytes, msgs, _, _ := alice.GetRekeyStats()
```

### Passphrase (PBKDF2 / Argon2id-lite)

```go
salt := qd.GenerateSalt(32)
k1 := qd.PBKDF2SyncBytes([]byte("password"), salt, 100000, 32) // RFC 6070 compatible
k2 := qd.Argon2idSyncBytes([]byte("password"), salt, 32, 3, 32)

key, salt := qd.DerivePassphrase("my secret", qd.PassphraseOptions{Algorithm: "argon2id"})
sess, mac := qd.DeriveKeyForQuarkDash("password", salt, qd.PassphraseOptions{Algorithm: "pbkdf2"})
```

### Transport Wrappers

```go
// HTTP
httpAlice := qd.NewQDHTTP(alice)
httpBob   := qd.NewQDHTTP(bob)
body, hdr, _ := httpAlice.EncryptBodyWithHeaders(map[string]string{"hello":"world"})
var out map[string]string
_ = httpBob.DecryptToJSON(body, &out)
http.Handle("/", httpAlice.Middleware(handler))

// gRPC
grpcAlice := qd.NewQDGRPC(alice)
grpcBob   := qd.NewQDGRPC(bob)
enc, _ := grpcAlice.EncryptMessage([]byte("payload"))
dec, _ := grpcBob.DecryptMessage(enc)

// WebSocket
wsAlice := qd.WrapWebSocket(alice, rawWS) // rawWS implements transport.WSLike
_ = wsAlice.Send(qd.TextToBytes("hello ws"))
wsAlice.OnDecrypted(func(d []byte){ fmt.Println(string(d)) })
```

---

## 📊 Benchmark

Launched at **Intel i5-13420H, Go 1.25, Fedora linux, 16GB RAM**:

```bash
# Basic benchmark with go bench:
go test -bench=. -benchmem

# Full featured benchmark with table:
go test -bench-report -v -run TestBenchmarkReport
```

### Benchmark results with (ms/op)

| Benchmark        | Time/op (ms) | Ops/sec | Speed (if available) |
|------------------|--------------|---------|----------------------|
| Key Generation   | 0.421 ms     | 2375    | -                    |
| Encapsulate      | 0.812 ms     | 1231    | -                    |
| Encrypt 1KB      | 0.011 ms     | 94994   | -                    |
| Decrypt 1KB      | 0.002 ms     | 401375  | -                    |
| Encrypt 1MB      | 10.275 ms    | 97      | 97.32 MB/s           |
| Decrypt 1MB      | 2.295 ms     | 436     | 435.69 MB/s          |
| ChaCha20 raw 1MB | 6.805 ms     | 147     | 146.96 MB/s          |
| Gimli raw 1MB    | 8.009 ms     | 125     | 124.85 MB/s          |


## 📖 API

| Category                 | Symbols                                                                                                                                                                                                                                   |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Core**                 | `New(opts...) *QuarkDash`, `GenerateKeyPair() []byte`, `InitializeSession(peer []byte, initiator bool) ([]byte,error)`, `FinalizeSession(ct []byte) error`, `Encrypt([]byte)([]byte,error)`, `Decrypt([]byte)([]byte,error)`, `Dispose()` |
| **KDF/MAC**              | `QuarkDashKDF`, `QuarkDashMAC`, `Shake256Hash`, `SHA256Hash`                                                                                                                                                                              |
| **Cipher**               | `CipherType`, `NewQuarkDashChaCha`, `NewQuarkDashGimli`, `ChaChaKeystream`, `GimliKeystream`                                                                                                                                              |
| **Utils**                | `TextToBytes`, `BytesToText`, `RandomBytes`, `ConcatBytes`, `BytesToHex`                                                                                                                                                                  |
| **Passphrase**           | `GenerateSalt`, `PBKDF2SyncBytes`, `Argon2idSyncBytes`, `DerivePassphrase`, `DeriveKeyForQuarkDash`                                                                                                                                       |
| **Rekey (Key rotation)** | `RekeyPolicy`, `DefaultRekeyPolicy`, `NeedsRekey()`, `Rekey()`, `ApplyRekey()`                                                                                                                                                            |
| **Ring LWE**             | `NewRRLWE()`, `NewRingLWE()`, `NTTProtectionOptions`                                                                                                                                                                                      |
| **Transport**            | `NewQDHTTP`, `NewQDGRPC`, `WrapWebSocket`, `WSLike`                                                                                                                                                                                       |

---

## 🧪 Tests

```bash
go test ./... -cover          # 66%
go test -run TestLarge -count=1
go test -bench=. -benchtime=2x # benchmarks
go vet ./...                   # stats
go test -race ./...            # race
```

---

## How it works?
Below I've outlined a brief step-by-step flowchart of how the algorithm works. If you need more detailed information, please [visit the Wiki](https://github.com/devsdaddy/quarkdash/wiki).

**Step-by-Step Algorithm:**
1. Key Pair Generation (using Ring‑LWE);
2. Session Setup (using SHAKE-256 emulated KEM);
3. Session Key Flow (KDF);
4. Message Encryption (AEAD);
5. Decryption;

> [Read more about algorithm in Wiki](https://github.com/devsdaddy/quarkdash) or [View scheme](https://app.holst.so/share/b/7ae942f8-8a40-42c9-9991-3b624f147da8)

**Have a questions?** [Contact me](mailto:ilya@neurosell.top)

---

## Licensing
**QuarkDash Crypto** library is distributed under the MIT license. You can use it however you like. I would appreciate any feedback and suggestions for improvement.
Full license text [can be found here](https://github.com/devsdaddy/quarkdash/blob/main/LICENSE)

---

[Paper](https://github.com/DevsDaddy/quarkdash/blob/main/whitepaper.pdf) | [About](#about-quarkdash-crypto) | [Get Started](#-installation) | [TypeScript Version](https://github.com/devsdaddy/quarkdash)