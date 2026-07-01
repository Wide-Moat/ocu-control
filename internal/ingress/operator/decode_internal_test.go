// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// countingReader wraps an io.Reader and records how many bytes were pulled through
// it, so a test can prove the decoder short-circuits at the cap rather than reading
// a whole oversized body into memory.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestDecodeJSONOversizedRejected proves the operator decodeJSON refuses an oversized
// body with a *http.MaxBytesError (the 413 path) AND that the whole oversized body is
// NOT read into memory: the underlying reader is far larger than the cap, yet the
// counting reader records at most maxBodyBytes+1 bytes pulled, proving the cap
// short-circuits the read. The head of the body is valid-JSON-shaped so the failure is
// the size cap, not a syntax error mid-stream. This is the operator mirror of the
// gateway white-box oversized test.
func TestDecodeJSONOversizedRejected(t *testing.T) {
	t.Parallel()

	// A multi-MB underlying body, far past the 64KiB cap, so the assertion that the
	// pull count is bounded by ~maxBodyBytes is non-vacuous.
	const underlying = 1 << 20
	payload := make([]byte, underlying)
	head := []byte(`{"session_hint":"`)
	copy(payload, head)
	for i := len(head); i < len(payload); i++ {
		payload[i] = 'A'
	}

	counter := &countingReader{r: bytes.NewReader(payload)}
	r := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", counter)
	r.ContentLength = -1 // do not let a known length cause an early reject elsewhere

	var v createBody
	err := decodeJSON(httptest.NewRecorder(), r, &v)
	if err == nil {
		t.Fatal("decodeJSON(oversized body) = nil; want a refusal")
	}
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("decodeJSON(oversized body) err = %v; want *http.MaxBytesError (the 413 path)", err)
	}
	if counter.n > maxBodyBytes+1 {
		t.Fatalf("read %d bytes of the oversized body; want <= %d (cap short-circuits the read)", counter.n, maxBodyBytes+1)
	}
	if counter.n >= underlying {
		t.Fatalf("read the whole %d-byte body into memory; the cap did not short-circuit", counter.n)
	}
}

// TestDecodeJSONNilAndEmptyBody proves the operator decodeJSON treats a nil body and
// an empty body as the zero value (no error) with the MaxBytesReader wrap in place:
// the nil-body guard stays first, so a nil body is never wrapped and decodes cleanly,
// and an empty body still maps its io.EOF to the zero value.
func TestDecodeJSONNilAndEmptyBody(t *testing.T) {
	t.Parallel()
	var v revokeAllBody
	rNil := httptest.NewRequest(http.MethodPost, "/x", nil)
	rNil.Body = nil
	if err := decodeJSON(httptest.NewRecorder(), rNil, &v); err != nil {
		t.Fatalf("decodeJSON(nil body) = %v; want nil", err)
	}
	rEmpty := httptest.NewRequest(http.MethodPost, "/x", http.NoBody)
	if err := decodeJSON(httptest.NewRecorder(), rEmpty, &v); err != nil {
		t.Fatalf("decodeJSON(empty body) = %v; want nil", err)
	}
}

// TestNewServerTimeoutsConfigured proves the operator server is built with the
// bounded read/idle posture: a zero ReadTimeout or IdleTimeout would be the bug this
// hardening closes. It asserts the actual *http.Server fields, not just the consts,
// so the assertion is non-vacuous.
func TestNewServerTimeoutsConfigured(t *testing.T) {
	t.Parallel()
	srv := newServer(context.Background(), http.NewServeMux())
	if srv.ReadHeaderTimeout != readHeaderTimeout || srv.ReadHeaderTimeout == 0 {
		t.Fatalf("ReadHeaderTimeout = %v; want non-zero %v", srv.ReadHeaderTimeout, readHeaderTimeout)
	}
	if srv.ReadTimeout != readTimeout || srv.ReadTimeout == 0 {
		t.Fatalf("ReadTimeout = %v; want non-zero %v (a zero whole-request read bound is the slow-body bug)", srv.ReadTimeout, readTimeout)
	}
	if srv.IdleTimeout != idleTimeout || srv.IdleTimeout == 0 {
		t.Fatalf("IdleTimeout = %v; want non-zero %v", srv.IdleTimeout, idleTimeout)
	}
	if readTimeout > idleTimeout {
		t.Fatalf("readTimeout %v > idleTimeout %v; the whole-request bound must not exceed the idle bound", readTimeout, idleTimeout)
	}
}
