/*
QuarkDash gRPC Wrapper

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package transport

import "encoding/json"

// QDGRPC - Wrapper for gRPC messages.
// Encrypt binary payload, save compatible with .proto without changes.
type QDGRPC struct {
	enc     Encryptor
	metaKey string
}

// NewQDGRPC create gRPC wrapper.
func NewQDGRPC(enc Encryptor, metaKey ...string) *QDGRPC {
	k := "qd-encrypted-bin"
	if len(metaKey) > 0 && metaKey[0] != "" {
		k = metaKey[0]
	}
	return &QDGRPC{enc: enc, metaKey: k}
}

// EncryptMessage encrypt message (bytes/string/struct→JSON).
func (g *QDGRPC) EncryptMessage(msg interface{}) ([]byte, error) {
	var b []byte
	switch v := msg.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		j, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		b = j
	}
	return g.enc.Encrypt(b)
}

// DecryptMessage decrypt message
func (g *QDGRPC) DecryptMessage(data []byte) ([]byte, error) { return g.enc.Decrypt(data) }

// DecryptMessageToJSON decrypt and parse JSON.
func (g *QDGRPC) DecryptMessageToJSON(data []byte, out interface{}) error {
	b, err := g.DecryptMessage(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// GrpcCall - simplified gRPC call for interceptors.
type GrpcCall struct {
	Metadata map[string]string
	Request  []byte
}

// ServerInterceptor - create sever interceptor: decrypt request, encrypt response.
func (g *QDGRPC) ServerInterceptor(call GrpcCall, next func(GrpcCall) (interface{}, error)) (interface{}, error) {
	if len(call.Request) > 0 {
		if dec, err := g.DecryptMessage(call.Request); err == nil {
			call.Request = dec
		}
	}
	res, err := next(call)
	if err != nil {
		return nil, err
	}
	switch v := res.(type) {
	case []byte:
		if enc, e2 := g.EncryptMessage(v); e2 == nil {
			return enc, nil
		}
	case map[string]interface{}:
		b, _ := json.Marshal(v)
		if enc, e2 := g.EncryptMessage(b); e2 == nil {
			return enc, nil
		}
	}
	return res, nil
}

// WrapClient wrap gRPC client - encrypt outcoming and decrypt incoming.
func (g *QDGRPC) WrapClient(client interface{}) interface{} {
	return &wrappedGRPCClient{orig: client, g: g}
}

type wrappedGRPCClient struct {
	orig interface{}
	g    *QDGRPC
}

func (w *wrappedGRPCClient) Invoke(method string, arg []byte) ([]byte, error) {
	enc, err := w.g.EncryptMessage(arg)
	if err != nil {
		return nil, err
	}
	if c, ok := w.orig.(interface {
		Invoke(string, []byte) ([]byte, error)
	}); ok {
		res, err := c.Invoke(method, enc)
		if err != nil {
			return nil, err
		}
		dec, err := w.g.DecryptMessage(res)
		if err != nil {
			return res, nil
		}
		return dec, nil
	}
	return enc, nil
}

// ToBytes convert data to bytes (helper).
func ToBytes(data interface{}) []byte {
	switch v := data.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		b, _ := json.Marshal(v)
		return b
	}
}
