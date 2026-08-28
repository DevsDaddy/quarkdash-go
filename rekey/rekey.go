/*
    QuarkDash Key Rotation Implementation

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package rekey

import (
	"errors"

	"github.com/DevsDaddy/quarkdash-go/core"
)

// RekeyPolicy setup when we need to rotate a keys
type RekeyPolicy struct {
	AfterBytes    int   // after N bytes of encryption
	AfterMessages int   // after N messages
	IntervalMs    int64 // after N ms (0 - without time limits)
}

// DefaultRekeyPolicy - default key rotation policy (64MB / 10k messages).
var DefaultRekeyPolicy = RekeyPolicy{
	AfterBytes:    64 * 1024 * 1024,
	AfterMessages: 10000,
	IntervalMs:    0,
}

// DeriveRekeyMaterial derive 64B new material from old session and keys
func DeriveRekeyMaterial(kdf core.KDF, oldKey, oldMac, salt []byte, counter int, infoExtra string) []byte {
	ikm := core.ConcatBytes(oldKey, oldMac)
	info := core.TextToBytes("quarkdash-rekey-v1:" + itoa(counter) + ":" + infoExtra)
	out := kdf.Derive(ikm, salt, info, 64)
	core.SecureZero(ikm)
	return out
}

// BuildRekeyPayload build a binary payload to salt exchange: [0x51 | counter LE32 | salt].
func BuildRekeyPayload(salt []byte, counter int) []byte {
	payload := make([]byte, 1+4+len(salt))
	payload[0] = 0x51 // magic "Q"
	payload[1] = byte(counter & 0xff)
	payload[2] = byte((counter >> 8) & 0xff)
	payload[3] = byte((counter >> 16) & 0xff)
	payload[4] = byte((counter >> 24) & 0xff)
	copy(payload[5:], salt)
	return payload
}

// ParseRekeyPayload parse payload and return salt and counter.
func ParseRekeyPayload(payload []byte) (salt []byte, counter int, err error) {
	if len(payload) < 5 || payload[0] != 0x51 {
		return nil, 0, errors.New("invalid rekey payload")
	}
	counter = int(payload[1]) | int(payload[2])<<8 | int(payload[3])<<16 | int(payload[4])<<24
	salt = payload[5:]
	if len(salt) != 32 {
		return nil, 0, errors.New("invalid rekey salt length")
	}
	cp := make([]byte, len(salt))
	copy(cp, salt)
	return cp, counter, nil
}

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
