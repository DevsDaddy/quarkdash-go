/*
    QuarkDash Key Ring-LWE Implementation

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package ringlwe

import (
	"errors"
	"math"

	"github.com/DevsDaddy/quarkdash-go/core"
	"github.com/DevsDaddy/quarkdash-go/hash"
)

var (
	ErrInvalidPublicKey  = errors.New("invalid public key length")
	ErrInvalidPrivateKey = errors.New("invalid private key length")
	ErrInvalidCiphertext = errors.New("invalid ciphertext length")
	ErrInvalidPoly       = errors.New("invalid poly length")
	ErrCoeffOutOfRange   = errors.New("poly coefficient out of range")
	ErrNTTFault          = errors.New("NTT fault detected: double-check mismatch")
)

type NTTProtectionOptions struct {
	Enabled        bool
	Blinding       bool
	DoubleCheck    bool
	ConstantTime   bool
	ValidateInputs bool
}

var DefaultNTTProtection = NTTProtectionOptions{
	Enabled:        true,
	Blinding:       true,
	DoubleCheck:    true,
	ConstantTime:   true,
	ValidateInputs: true,
}

type BaseRingLWE struct {
	N            int
	Q            int64
	Root         int64
	InvN         int64
	prot         NTTProtectionOptions
	wlenCache    map[int]int64
	invWlenCache map[int]int64
}

func newBaseRingLWE(n int, q, root int64) *BaseRingLWE {
	b := &BaseRingLWE{
		N:            n,
		Q:            q,
		Root:         root,
		prot:         DefaultNTTProtection,
		wlenCache:    make(map[int]int64),
		invWlenCache: make(map[int]int64),
	}
	b.InvN = b.modInverse(int64(n), q)
	return b
}

func (b *BaseRingLWE) SetNTTProtection(opts NTTProtectionOptions) { b.prot = opts }
func (b *BaseRingLWE) GetNTTProtection() NTTProtectionOptions     { return b.prot }

func (b *BaseRingLWE) modInverse(a, m int64) int64 {
	var oldR, r = a, m
	var oldS, s = int64(1), int64(0)
	for r != 0 {
		q := oldR / r
		oldR, r = r, oldR-q*r
		oldS, s = s, oldS-q*s
	}
	return ((oldS % m) + m) % m
}

func (b *BaseRingLWE) powMod(base, exp, mod int64) int64 {
	var result int64 = 1
	bb := base % mod
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = (result * bb) % mod
		}
		bb = (bb * bb) % mod
		e >>= 1
	}
	return result
}

// roundToBits - 2*v > Q ? 1 : 0
func (b *BaseRingLWE) roundToBits(poly []int64) []byte {
	out := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		if 2*poly[i] > b.Q {
			out[i>>3] |= 1 << (i & 7)
		}
	}
	return out
}

func (b *BaseRingLWE) helpRec(v int64) int {
	if 4*v < b.Q {
		return 0
	}
	if 2*v < b.Q {
		return 1
	}
	if 4*v < 3*b.Q {
		return 0
	}
	return 1
}

func (b *BaseRingLWE) rec(v int64, hint int) int {
	eightVp := 8 * v
	Q := b.Q
	var c0, c1 int64
	if hint == 0 {
		c0 = Q
		c1 = 5 * Q
	} else {
		c0 = 3 * Q
		c1 = 7 * Q
	}
	dist := func(target int64) int64 {
		d := eightVp - target
		if d < 0 {
			d = -d
		}
		if d > 4*Q {
			d = 8*Q - d
		}
		return d
	}
	if dist(c0) < dist(c1) {
		return 0
	}
	return 1
}

func (b *BaseRingLWE) roundToBitsWithHint(poly []int64) (bits []byte, hint []byte) {
	bits = make([]byte, 32)
	hint = make([]byte, 32)
	for i := 0; i < b.N; i++ {
		if 2*poly[i] > b.Q {
			bits[i>>3] |= 1 << (i & 7)
		}
		if b.helpRec(poly[i]) == 1 {
			hint[i>>3] |= 1 << (i & 7)
		}
	}
	return
}

func (b *BaseRingLWE) recToBits(poly []int64, hint []byte) []byte {
	out := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		h := (hint[i>>3] >> (i & 7)) & 1
		if b.rec(poly[i], int(h)) == 1 {
			out[i>>3] |= 1 << (i & 7)
		}
	}
	return out
}

func (b *BaseRingLWE) validatePoly(poly []int64) error {
	if len(poly) != b.N {
		return ErrInvalidPoly
	}
	if b.prot.ValidateInputs {
		for _, v := range poly {
			if v < -b.Q || v >= b.Q {
				return ErrCoeffOutOfRange
			}
		}
	}
	return nil
}

func (b *BaseRingLWE) validatePublicKey(pk []byte) error {
	if len(pk) != b.N*4 {
		return ErrInvalidPublicKey
	}
	return nil
}

func (b *BaseRingLWE) validatePrivateKey(sk []byte) error {
	if len(sk) != b.N*2 {
		return ErrInvalidPrivateKey
	}
	return nil
}

func (b *BaseRingLWE) validateCiphertext(ct []byte) error {
	if len(ct) != b.N*2 && len(ct) != b.N*2+32 {
		return ErrInvalidCiphertext
	}
	return nil
}

func (b *BaseRingLWE) deserializePoly(data []byte) []int64 {
	poly := make([]int64, b.N)
	for i := 0; i < b.N; i++ {
		val := int64(data[2*i]) | int64(data[2*i+1])<<8
		if val >= b.Q && b.prot.ValidateInputs {
			val = val % b.Q
		}
		poly[i] = val
	}
	return poly
}

func (b *BaseRingLWE) serializePoly(poly []int64) []byte {
	out := make([]byte, b.N*2)
	for i := 0; i < b.N; i++ {
		norm := ((poly[i] % b.Q) + b.Q) % b.Q
		out[2*i] = byte(norm & 0xff)
		out[2*i+1] = byte((norm >> 8) & 0xff)
	}
	return out
}

func (b *BaseRingLWE) normalizePoly(poly []int64) []int64 {
	out := make([]int64, len(poly))
	for i, v := range poly {
		out[i] = ((v % b.Q) + b.Q) % b.Q
	}
	return out
}

func (b *BaseRingLWE) getWlen(length int) int64 {
	if v, ok := b.wlenCache[length]; ok {
		return v
	}
	v := b.powMod(b.Root, int64(b.N/length), b.Q)
	b.wlenCache[length] = v
	return v
}

func (b *BaseRingLWE) getInvWlen(length int) int64 {
	if v, ok := b.invWlenCache[length]; ok {
		return v
	}
	w := b.getWlen(length)
	v := b.modInverse(w, b.Q)
	b.invWlenCache[length] = v
	return v
}

func (b *BaseRingLWE) bitReverse(a []int64) []int64 {
	n := len(a)
	res := make([]int64, n)
	copy(res, a)
	j := 0
	for i := 1; i < n; i++ {
		bit := n >> 1
		for ; j&bit != 0; bit >>= 1 {
			j ^= bit
		}
		j ^= bit
		if i < j {
			res[i], res[j] = res[j], res[i]
		}
	}
	return res
}

func (b *BaseRingLWE) ntt(poly []int64) []int64 {
	res := b.bitReverse(poly)
	length := 2
	for length <= b.N {
		wlen := b.powMod(b.Root, int64(b.N/length), b.Q)
		for i := 0; i < b.N; i += length {
			w := int64(1)
			for j := 0; j < length/2; j++ {
				u := res[i+j]
				v := (res[i+j+length/2] * w) % b.Q
				res[i+j] = (u + v) % b.Q
				res[i+j+length/2] = (u - v + b.Q) % b.Q
				w = (w * wlen) % b.Q
			}
		}
		length <<= 1
	}
	return res
}

func (b *BaseRingLWE) invNTT(poly []int64) []int64 {
	res := b.bitReverse(poly)
	length := 2
	for length <= b.N {
		wlen := b.modInverse(b.powMod(b.Root, int64(b.N/length), b.Q), b.Q)
		for i := 0; i < b.N; i += length {
			w := int64(1)
			for j := 0; j < length/2; j++ {
				u := res[i+j]
				v := (res[i+j+length/2] * w) % b.Q
				res[i+j] = (u + v) % b.Q
				res[i+j+length/2] = (u - v + b.Q) % b.Q
				w = (w * wlen) % b.Q
			}
		}
		length <<= 1
	}
	for i := 0; i < b.N; i++ {
		res[i] = (res[i] * b.InvN) % b.Q
	}
	return res
}

func (b *BaseRingLWE) hardenedNTT(poly []int64) []int64 {
	res := b.bitReverse(poly)
	length := 2
	for length <= b.N {
		wlen := b.getWlen(length)
		for i := 0; i < b.N; i += length {
			w := int64(1)
			for j := 0; j < length/2; j++ {
				u := res[i+j]
				v := (res[i+j+length/2] * w) % b.Q
				res[i+j] = (u + v) % b.Q
				res[i+j+length/2] = (u - v + b.Q) % b.Q
				w = (w * wlen) % b.Q
			}
		}
		length <<= 1
	}
	return res
}

func (b *BaseRingLWE) hardenedInvNTT(poly []int64) []int64 {
	res := b.bitReverse(poly)
	length := 2
	for length <= b.N {
		wlen := b.getInvWlen(length)
		for i := 0; i < b.N; i += length {
			w := int64(1)
			for j := 0; j < length/2; j++ {
				u := res[i+j]
				v := (res[i+j+length/2] * w) % b.Q
				res[i+j] = (u + v) % b.Q
				res[i+j+length/2] = (u - v + b.Q) % b.Q
				w = (w * wlen) % b.Q
			}
		}
		length <<= 1
	}
	for i := 0; i < b.N; i++ {
		res[i] = (res[i] * b.InvN) % b.Q
	}
	return res
}

func (b *BaseRingLWE) secureMultiply(a, bPoly []int64) []int64 {
	if b.prot.ValidateInputs {
		if err := b.validatePoly(a); err != nil {
			panic(err)
		}
		if err := b.validatePoly(bPoly); err != nil {
			panic(err)
		}
	}
	aNorm := b.normalizePoly(a)
	bNorm := b.normalizePoly(bPoly)
	if !b.prot.Enabled {
		aNTT := b.ntt(aNorm)
		bNTT := b.ntt(bNorm)
		prod := make([]int64, b.N)
		for i := 0; i < b.N; i++ {
			prod[i] = (aNTT[i] * bNTT[i]) % b.Q
		}
		return b.invNTT(prod)
	}
	aEff := aNorm
	bEff := bNorm
	if b.prot.Blinding {
		rnd := core.RandomBytes(2)
		bf := (int64(rnd[0])|int64(rnd[1])<<8)%(b.Q-1) + 1
		inv := b.modInverse(bf, b.Q)
		aEff = make([]int64, b.N)
		bEff = make([]int64, b.N)
		for i := 0; i < b.N; i++ {
			aEff[i] = (aNorm[i] * bf) % b.Q
			bEff[i] = (bNorm[i] * inv) % b.Q
		}
	}
	aNTT := b.hardenedNTT(aEff)
	bNTT := b.hardenedNTT(bEff)
	prod := make([]int64, b.N)
	for i := 0; i < b.N; i++ {
		prod[i] = (aNTT[i] * bNTT[i]) % b.Q
	}
	res := b.hardenedInvNTT(prod)
	if b.prot.DoubleCheck {
		aNTT2 := b.hardenedNTT(aEff)
		bNTT2 := b.hardenedNTT(bEff)
		prod2 := make([]int64, b.N)
		for i := 0; i < b.N; i++ {
			prod2[i] = (aNTT2[i] * bNTT2[i]) % b.Q
		}
		res2 := b.hardenedInvNTT(prod2)
		for i := 0; i < b.N; i++ {
			if res[i] != res2[i] {
				panic(ErrNTTFault)
			}
		}
	}
	return res
}

func (b *BaseRingLWE) uniformPoly() []int64 {
	poly := make([]int64, b.N)
	by := core.RandomBytes(b.N * 2)
	for i := 0; i < b.N; i++ {
		val := (int64(by[2*i]) | int64(by[2*i+1])<<8) % b.Q
		poly[i] = val
	}
	return poly
}

func (b *BaseRingLWE) smallPoly() []int64 {
	poly := make([]int64, b.N)
	bytesNeeded := (b.N*2 + 7) / 8
	rb := core.RandomBytes(bytesNeeded)
	for i := 0; i < b.N; i++ {
		byteIdx := (i * 2) / 8
		bitShift := (i * 2) % 8
		val := (rb[byteIdx] >> bitShift) & 0x03
		if val == 0 {
			poly[i] = -1
		} else if val == 1 {
			poly[i] = 0
		} else {
			poly[i] = 1
		}
	}
	return poly
}

func (b *BaseRingLWE) errorPoly() []int64 {
	poly := make([]int64, b.N)
	const sigma = 3.19
	for i := 0; i < b.N; i++ {
		rb := core.RandomBytes(12)
		sum := 0
		for j := 0; j < 12; j++ {
			sum += int(rb[j])
		}
		centered := float64(sum)/255 - 6
		errVal := int(math.Floor(centered * sigma))
		if errVal < -int(b.Q) {
			errVal = -int(b.Q)
		}
		if errVal >= int(b.Q) {
			errVal = int(b.Q) - 1
		}
		poly[i] = int64(errVal)
	}
	return poly
}

func (b *BaseRingLWE) hashSharedSecret(ss, pubKey, ciphertext []byte) []byte {
	return hash.SHA256Hash(core.ConcatBytes(ss, pubKey, ciphertext))
}

func (b *BaseRingLWE) GenerateKeyPair() (publicKey, privateKey []byte) {
	a := b.uniformPoly()
	s := b.smallPoly()
	e := b.errorPoly()
	as := b.secureMultiply(a, s)
	bp := make([]int64, b.N)
	for i := 0; i < b.N; i++ {
		bp[i] = ((as[i]+e[i])%b.Q + b.Q) % b.Q
	}
	pub := core.ConcatBytes(b.serializePoly(a), b.serializePoly(bp))
	priv := b.serializePoly(s)
	return pub, priv
}

func (b *BaseRingLWE) Encapsulate(pubKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if err = b.validatePublicKey(pubKey); err != nil {
		return nil, nil, err
	}
	a := b.deserializePoly(pubKey[:b.N*2])
	bp := b.deserializePoly(pubKey[b.N*2:])
	sp := b.smallPoly()
	ep := b.errorPoly()
	uArr := b.secureMultiply(a, sp)
	for i := 0; i < b.N; i++ {
		uArr[i] = ((uArr[i]+ep[i])%b.Q + b.Q) % b.Q
	}
	w := b.secureMultiply(bp, sp)
	bits, hint := b.roundToBitsWithHint(w)
	uBytes := b.serializePoly(uArr)
	ct := core.ConcatBytes(uBytes, hint)
	ss := b.hashSharedSecret(bits, pubKey, ct)
	return ct, ss, nil
}

func (b *BaseRingLWE) Decapsulate(privKey, peerPubKey, ciphertext []byte) ([]byte, error) {
	if err := b.validatePrivateKey(privKey); err != nil {
		return nil, err
	}
	if err := b.validateCiphertext(ciphertext); err != nil {
		return nil, err
	}
	if err := b.validatePublicKey(peerPubKey); err != nil {
		return nil, err
	}
	s := b.deserializePoly(privKey)
	var u []int64
	var hint []byte
	if len(ciphertext) == b.N*2+32 {
		u = b.deserializePoly(ciphertext[:b.N*2])
		hint = ciphertext[b.N*2:]
	} else {
		u = b.deserializePoly(ciphertext)
		wTmp := b.secureMultiply(u, s)
		rawTmp := b.roundToBits(wTmp)
		return b.hashSharedSecret(rawTmp, peerPubKey, ciphertext), nil
	}
	w := b.secureMultiply(u, s)
	rawSecret := b.recToBits(w, hint)
	return b.hashSharedSecret(rawSecret, peerPubKey, ciphertext), nil
}

func (b *BaseRingLWE) ValidatePublicKey(pk []byte) error { return b.validatePublicKey(pk) }
func (b *BaseRingLWE) ValidateCiphertext(ct []byte) error { return b.validateCiphertext(ct) }

type RingLWE struct{ *BaseRingLWE }
type RRLWE struct{ *BaseRingLWE }

func NewRingLWE() *RingLWE { return &RingLWE{newBaseRingLWE(256, 7681, 5685)} }
func NewRRLWE() *RRLWE     { return &RRLWE{newBaseRingLWE(256, 12289, 8340)} }

func (r *RingLWE) GenerateKeyPair() (pub, priv []byte) { return r.BaseRingLWE.GenerateKeyPair() }
func (r *RingLWE) Encapsulate(pub []byte) ([]byte, []byte, error) {
	return r.BaseRingLWE.Encapsulate(pub)
}
func (r *RingLWE) Decapsulate(priv, peerPub, ct []byte) ([]byte, error) {
	return r.BaseRingLWE.Decapsulate(priv, peerPub, ct)
}
func (r *RRLWE) GenerateKeyPair() (pub, priv []byte) { return r.BaseRingLWE.GenerateKeyPair() }
func (r *RRLWE) Encapsulate(pub []byte) ([]byte, []byte, error) {
	return r.BaseRingLWE.Encapsulate(pub)
}
func (r *RRLWE) Decapsulate(priv, peerPub, ct []byte) ([]byte, error) {
	return r.BaseRingLWE.Decapsulate(priv, peerPub, ct)
}
