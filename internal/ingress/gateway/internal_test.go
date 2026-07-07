// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/registry"
)

// errUnclassified is a refusal that is neither unattested nor not-owned, so
// writeServiceError maps it to the default 409.
var errUnclassified = errors.New("gateway_internal_test: unclassified refusal")

// contextWithGatewayMarker stamps the same ConnContext marker Serve stamps, so
// connInfoFromRequest treats the request as served through Serve.
func contextWithGatewayMarker(r *http.Request) context.Context {
	return context.WithValue(r.Context(), connInfoKey{}, ingress.ChannelGateway)
}

// TestVerifiedSANsOfNilAndEmpty proves verifiedSANsOf fails closed on a nil state
// and a handshake state with no verified chain: both yield no SAN, so the resolver
// refuses.
func TestVerifiedSANsOfNilAndEmpty(t *testing.T) {
	t.Parallel()
	if sans := verifiedSANsOf(nil); sans != nil {
		t.Fatalf("verifiedSANsOf(nil) = %v; want nil", sans)
	}
	if sans := verifiedSANsOf(&tls.ConnectionState{}); sans != nil {
		t.Fatalf("verifiedSANsOf(empty state) = %v; want nil (no verified chain)", sans)
	}
}

// TestVerifiedSANsOfReadsVerifiedChain proves verifiedSANsOf reads ONLY the leaf of
// the first verified chain (DNS + URI SANs), never the raw presented cert: a
// populated VerifiedChains yields its leaf's SANs.
func TestVerifiedSANsOfReadsVerifiedChain(t *testing.T) {
	t.Parallel()
	uri, _ := url.Parse("spiffe://td.test/acme/worker-7")
	leaf := &x509.Certificate{
		DNSNames: []string{"svc.internal"},
		URIs:     []*url.URL{uri},
	}
	st := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	sans := verifiedSANsOf(st)
	if len(sans) != 2 {
		t.Fatalf("verifiedSANsOf = %v; want the DNS and URI SANs", sans)
	}
	if sans[0] != "svc.internal" || sans[1] != "spiffe://td.test/acme/worker-7" {
		t.Fatalf("verifiedSANsOf = %v; want [svc.internal spiffe://td.test/acme/worker-7]", sans)
	}
}

// TestConnInfoFromRequestAbsentMarker proves connInfoFromRequest fails closed for a
// request not served through Serve (no channel marker on the context): it yields a
// gateway-channel ConnInfo with no SANs, so the resolver refuses.
func TestConnInfoFromRequestAbsentMarker(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil)
	info := connInfoFromRequest(r)
	if info.Channel != ingress.ChannelGateway {
		t.Fatalf("ConnInfo channel = %v; want ChannelGateway", info.Channel)
	}
	if len(info.CertSANs) != 0 {
		t.Fatalf("ConnInfo CertSANs = %v; want none (request not served through Serve)", info.CertSANs)
	}
}

// TestConnInfoFromRequestWithMarkerAndTLS proves connInfoFromRequest derives the
// verified SANs from r.TLS when the channel marker is present: the marked,
// handshake-complete request carries the verified leaf's SANs.
func TestConnInfoFromRequestWithMarkerAndTLS(t *testing.T) {
	t.Parallel()
	uri, _ := url.Parse("spiffe://td.test/acme/worker-7")
	leaf := &x509.Certificate{URIs: []*url.URL{uri}}
	r := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil)
	r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	// Mark the request as served through Serve (the ConnContext marker).
	ctx := contextWithGatewayMarker(r)
	info := connInfoFromRequest(r.WithContext(ctx))
	if len(info.CertSANs) != 1 || info.CertSANs[0] != "spiffe://td.test/acme/worker-7" {
		t.Fatalf("ConnInfo CertSANs = %v; want the verified URI SAN", info.CertSANs)
	}
}

// TestWriteServiceErrorDefaultIs409 proves writeServiceError maps an unclassified
// refusal (neither unattested nor not-owned) to 409.
func TestWriteServiceErrorDefaultIs409(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeServiceError(rec, errUnclassified)
	if rec.Code != http.StatusConflict {
		t.Fatalf("writeServiceError(unclassified) = %d; want 409", rec.Code)
	}
}

// TestWriteServiceErrorInvalidArgumentIs400 is the keystone for the request-derived
// invalid-argument arm: a lifecycle.ErrInvalidArgument (e.g. no resolvable guest
// image) maps to 400, NOT the 409 default. This is the client-error class — the
// refusal is a pure function of the request + fixed config, consults no tenant
// state, and so is safe to surface (unlike the 409/404 collapse that hides
// cross-tenant existence). Red-probe: delete the ErrInvalidArgument arm in
// writeServiceError → this falls through to 409 and reds.
func TestWriteServiceErrorInvalidArgumentIs400(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeServiceError(rec, lifecycle.ErrInvalidArgument)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("writeServiceError(ErrInvalidArgument) = %d; want 400", rec.Code)
	}
	// A not-owned refusal must STILL be 404, never collapsed into the new 400 arm —
	// the arm is narrow (request-derived only), so it must not swallow the
	// existence-hiding 404.
	rec404 := httptest.NewRecorder()
	writeServiceError(rec404, registry.ErrNotOwned)
	if rec404.Code != http.StatusNotFound {
		t.Fatalf("writeServiceError(ErrNotOwned) = %d; want 404 (the 400 arm must not swallow it)", rec404.Code)
	}

	// The 400 body must NOT reflect the request-derived detail the Manager wraps
	// into the sentinel (e.g. the rejected image name, a caller-supplied value). The
	// Manager wraps user input — `fmt.Errorf("%w: guest image %q is not in the
	// allow-list", ErrInvalidArgument, in.Image)` — so echoing err.Error() back into
	// the response body reflects attacker-controlled bytes to the client (a taint
	// flow gosec flags as G705). The arm surfaces a fixed client-error string; the
	// status code carries the class, not the raw internal detail. Red-probe: change
	// the arm to write err.Error() → this reds on the reflected marker.
	const attackerMarker = "reflected-injection-marker-9f3a2b"
	wrapped := fmt.Errorf("%w: guest image %q is not in the allow-list", lifecycle.ErrInvalidArgument, attackerMarker)
	recEcho := httptest.NewRecorder()
	writeServiceError(recEcho, wrapped)
	if recEcho.Code != http.StatusBadRequest {
		t.Fatalf("writeServiceError(wrapped ErrInvalidArgument) = %d; want 400", recEcho.Code)
	}
	if strings.Contains(recEcho.Body.String(), attackerMarker) {
		t.Fatalf("400 body reflects request-derived detail %q (body=%q); it must surface a fixed string, never echo caller input", attackerMarker, recEcho.Body.String())
	}
}

// TestDecodeJSONEmptyAndNilBody proves decodeJSON treats a nil body and an empty
// body as the zero value (no error), so a parameterless POST decodes cleanly. The
// nil-body case also proves the MaxBytesReader wrap is skipped for a nil body (the
// guard order is preserved), so it does not panic on a nil ReadCloser.
func TestDecodeJSONEmptyAndNilBody(t *testing.T) {
	t.Parallel()
	var v hintBody
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

// TestDecodeJSONOversizedRejected proves decodeJSON refuses an oversized body with a
// *http.MaxBytesError (the 413 path) AND that the whole oversized body is NOT read
// into memory: the underlying reader is far larger than the cap, yet the counting
// reader records at most maxBodyBytes+1 bytes pulled, proving the cap short-circuits
// the read. The head of the body is valid-JSON-shaped so the failure is the size cap,
// not a syntax error mid-stream.
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

	var v hintBody
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

// TestNewServerTimeoutsConfigured proves the gateway server is built with the
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
