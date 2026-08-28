/*
    QuarkDash WebSocket Transport Wrapper

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package transport

import "encoding/json"

// WSLike - minimalistic WebSocket interface (compatible with gorilla/nhooyr and browser WS).
type WSLike interface {
	Send(data []byte) error
	OnMessage(handler func(data []byte))
	Close() error
}

// QDWebSocket - WebSocket messages wrapper.
type QDWebSocket struct {
	enc      Encryptor
	ws       WSLike
	handlers []func([]byte)
}

// NewQDWebSocket create a wrapper and subscribe to messages
func NewQDWebSocket(enc Encryptor, ws WSLike) *QDWebSocket {
	q := &QDWebSocket{enc: enc, ws: ws}
	q.attach()
	return q
}

// WrapWebSocket - alias for NewQDWebSocket.
func WrapWebSocket(enc Encryptor, ws WSLike) *QDWebSocket { return NewQDWebSocket(enc, ws) }

// Send encrypt and send binary data.
func (q *QDWebSocket) Send(data []byte) error {
	enc, err := q.enc.Encrypt(data)
	if err != nil {
		return err
	}
	return q.ws.Send(enc)
}

// SendString send string.
func (q *QDWebSocket) SendString(s string) error { return q.Send([]byte(s)) }

// SendJSON marshal and send objects as JSON.
func (q *QDWebSocket) SendJSON(obj interface{}) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return q.Send(b)
}

// OnDecrypted subscribe on decrypted messages.
func (q *QDWebSocket) OnDecrypted(handler func(data []byte)) {
	q.handlers = append(q.handlers, handler)
}

func (q *QDWebSocket) attach() {
	q.ws.OnMessage(func(data []byte) {
		dec, err := q.enc.Decrypt(data)
		if err != nil {
			return
		}
		for _, h := range q.handlers {
			h(dec)
		}
	})
}

// ToUint8Array - helper for data conversion.
func ToUint8Array(data interface{}) []byte {
	switch v := data.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}
