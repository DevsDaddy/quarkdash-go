/*
QuarkDash HTTP Wrapper

@git             https://github.com/devsdaddy/quarkdash-go
@version         1.2.1
@author          Elijah Rastorguev
@build           1023
@website         https://dev.to/devsdaddy
@updated         28.08.2026
*/
package transport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// Encryptor - minimal encryption interface
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// QDHTTPOptions - HTTP Wrapper options
type QDHTTPOptions struct {
	HeaderName string // header to mark encryption, by default "x-qd-encrypted"
}

// QDHTTP - Wrapper over HTTP and middleware.
type QDHTTP struct {
	enc  Encryptor
	opts QDHTTPOptions
}

// NewQDHTTP create a HTTP-wrapper.
func NewQDHTTP(enc Encryptor, opts ...QDHTTPOptions) *QDHTTP {
	o := QDHTTPOptions{HeaderName: "x-qd-encrypted"}
	if len(opts) > 0 && opts[0].HeaderName != "" {
		o = opts[0]
	}
	return &QDHTTP{enc: enc, opts: o}
}

// EncryptBody encrypt request body and return header marker.
func (h *QDHTTP) EncryptBody(body []byte) ([]byte, http.Header, error) {
	enc, err := h.enc.Encrypt(body)
	if err != nil {
		return nil, nil, err
	}
	hdr := http.Header{}
	hdr.Set(h.opts.HeaderName, "1")
	hdr.Set("Content-Type", "application/octet-stream")
	return enc, hdr, nil
}

// EncryptBodyWithHeaders encrypt request body (bytes/string/struct→JSON).
func (h *QDHTTP) EncryptBodyWithHeaders(body interface{}) ([]byte, http.Header, error) {
	var b []byte
	switch v := body.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		j, err := json.Marshal(v)
		if err != nil {
			return nil, nil, err
		}
		b = j
	}
	return h.EncryptBody(b)
}

// DecryptBody decrypt body.
func (h *QDHTTP) DecryptBody(data []byte) ([]byte, error) { return h.enc.Decrypt(data) }

// DecryptToString decrypt to string.
func (h *QDHTTP) DecryptToString(data []byte) (string, error) {
	b, err := h.DecryptBody(data)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecryptToJSON decrypt and parse JSON.
func (h *QDHTTP) DecryptToJSON(data []byte, out interface{}) error {
	b, err := h.DecryptBody(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Middleware - net/http middleware for encryption.
// Decrypt incoming requests with header and encrypt response.
func (h *QDHTTP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(h.opts.HeaderName) != "" {
			body, err := io.ReadAll(r.Body)
			if err == nil {
				dec, err2 := h.DecryptBody(body)
				if err2 == nil {
					r.Body = io.NopCloser(bytes.NewReader(dec))
					r.Header.Set("X-QD-Decrypted", "1")
				}
			}
		}
		rec := &responseRecorder{ResponseWriter: w, header: make(http.Header)}
		next.ServeHTTP(rec, r)
		if rec.body != nil {
			enc, err := h.enc.Encrypt(rec.body)
			if err == nil {
				w.Header().Set(h.opts.HeaderName, "1")
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(enc)
				return
			}
		}
		if rec.status != 0 {
			w.WriteHeader(rec.status)
		}
		if rec.body != nil {
			w.Write(rec.body)
		}
	})
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	body   []byte
	header http.Header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}
func (r *responseRecorder) WriteHeader(statusCode int) { r.status = statusCode }

// EncryptRequest encrypt body of http.Request before send.
func (h *QDHTTP) EncryptRequest(req *http.Request) error {
	if req.Body == nil {
		return nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	enc, err := h.enc.Encrypt(body)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(enc))
	req.Header.Set(h.opts.HeaderName, "1")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(enc))
	return nil
}

// DecryptResponse decrypt response if they marked with header.
func (h *QDHTTP) DecryptResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get(h.opts.HeaderName) != "" {
		return h.DecryptBody(body)
	}
	return body, nil
}
