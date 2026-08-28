/*
QuarkDash MAC Implementation

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package core

// Using hash helpers
import "github.com/DevsDaddy/quarkdash-go/hash"

// MAC an interface for message authentication
type MAC interface {
	Sign(data, key []byte) []byte
	SignTwo(data1, data2, key []byte) []byte
	Verify(data, key, tag []byte) bool
}

/*
QuarkDash MAC uses SHAKE256(key||data) -> 32B tag
In this implementation we use reusable buffer for SignTwo
to avoid allocations at hot way
*/
type QuarkDashMAC struct {
	buf []byte // Reusable buffer up to 64KB
}

// NewQuarkDashMAC Creates new MAC with default buffer
func NewQuarkDashMAC() *QuarkDashMAC {
	return &QuarkDashMAC{buf: make([]byte, 64*1024)}
}

// Sign compute tag for one piece of data using: SHAKE256(key||data, 32).
func (m *QuarkDashMAC) Sign(data, key []byte) []byte {
	full := ConcatBytes(key, data)
	return hash.Shake256(full, 32)
}

// SignTwo compute a tag for two piece of data without concat: SHAKE256(key||data1||data2).
// Data use reusable buffer
func (m *QuarkDashMAC) SignTwo(data1, data2, key []byte) []byte {
	total := len(key) + len(data1) + len(data2)
	if total > len(m.buf) {
		m.buf = make([]byte, total)
	}
	copy(m.buf, key)
	copy(m.buf[len(key):], data1)
	copy(m.buf[len(key)+len(data1):], data2)
	return hash.Shake256(m.buf[:total], 32)
}

// Verify check tag for constat time (timing-attack security)
func (m *QuarkDashMAC) Verify(data, key, tag []byte) bool {
	exp := m.Sign(data, key)
	return ConstantTimeEqual(exp, tag)
}

// VerifyTwo check tag for two pieces of data
func (m *QuarkDashMAC) VerifyTwo(data1, data2, key, tag []byte) bool {
	exp := m.SignTwo(data1, data2, key)
	return ConstantTimeEqual(exp, tag)
}
