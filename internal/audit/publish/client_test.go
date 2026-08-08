// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package publish_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/audit/publish"
)

// validWire is an envelope that satisfies every contract rule, so a test can make one
// field wrong at a time and know the refusal came from that field.
func validWire() ocsf.PublishWire {
	return ocsf.PublishWire{
		TraceID:   "3f2b1c",
		SessionID: "tenant/sess-1",
		ActorID:   "operator@example",
		Resource:  "session/tenant/sess-1",
		Action:    "create",
		Outcome:   "success",
		Sequence:  7,
		Payload:   json.RawMessage(`{"class_uid":3001}`),
	}
}

// newTestClient wires the real Client at a local server, so the request building,
// envelope validation, and status handling under test are the production paths.
func newTestClient(t *testing.T, h http.HandlerFunc) (*publish.Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := publish.NewWithHTTPClient(srv.Client(), srv.URL, "")
	if err != nil {
		t.Fatalf("NewWithHTTPClient: %v", err)
	}
	return c, srv
}

// TestPublish_ConflictIsAnErrorNotSwallowed is the load-bearing test of this package.
// A 409 from the ingest means the per-source sequence did NOT advance -- a real
// ordering conflict. It must surface as an error so the composite writer fails closed
// and the privileged action is denied.
//
// This exists because the code it guards was written against a comment claiming
// "idempotent 409/200 dedup". That reading is inverted: the ingest acknowledges a
// duplicate with 200, and reserves 409 for a regression. A client built on the
// comment would map 409 to success and drop precisely the events whose ordering
// broke -- silently, since nothing else in the chain re-checks it.
func TestPublish_ConflictIsAnErrorNotSwallowed(t *testing.T) {
	t.Parallel()
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sequence not monotonic", http.StatusConflict)
	})

	err := c.Publish(context.Background(), validWire())
	if err == nil {
		t.Fatal("Publish returned nil on HTTP 409; a sequence conflict must never be reported as committed")
	}
	if !errors.Is(err, publish.ErrSequenceConflict) {
		t.Fatalf("Publish on 409 = %v, want ErrSequenceConflict", err)
	}
}

// TestPublish_OnlyAcknowledgementIsSuccess pins that exactly one status class means
// committed. Every other status -- including the ones that look like someone else's
// problem (401/403 from a bad client cert, 404 for an unknown channel) -- is "not
// committed", because the caller's decision is the same in all of them: deny.
func TestPublish_OnlyAcknowledgementIsSuccess(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status  int
		wantErr error
	}{
		{http.StatusOK, nil},
		{http.StatusConflict, publish.ErrSequenceConflict},
		{http.StatusBadRequest, publish.ErrNotCommitted},
		{http.StatusUnauthorized, publish.ErrNotCommitted},
		{http.StatusForbidden, publish.ErrNotCommitted},
		{http.StatusNotFound, publish.ErrNotCommitted},
		{http.StatusServiceUnavailable, publish.ErrNotCommitted},
		{http.StatusInternalServerError, publish.ErrNotCommitted},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			t.Parallel()
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})
			err := c.Publish(context.Background(), validWire())
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("HTTP %d: Publish = %v, want nil (an acknowledgement is a commit)", tc.status, err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("HTTP %d: Publish = %v, want %v", tc.status, err, tc.wantErr)
			}
		})
	}
}

// TestPublish_SendsTheContractShape asserts what actually goes on the wire: the
// method and route the binding specifies, the channel address in the path, and a body
// carrying the seven mandatory fields and NOT the three the pipeline authors. A
// source that published its own source/prev_hash/chain_hash would be asserting chain
// state it has no authority over.
func TestPublish_SendsTheContractShape(t *testing.T) {
	t.Parallel()
	var gotMethod, gotPath string
	var gotBody map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	})

	if err := c.Publish(context.Background(), validWire()); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if want := "/v1alpha/audit/" + publish.ControlPlaneChannel; gotPath != want {
		t.Errorf("path = %q, want %q (the channel address is the last path segment)", gotPath, want)
	}
	for _, k := range []string{"trace_id", "session_id", "actor_id", "resource", "action", "outcome", "sequence", "payload"} {
		if _, ok := gotBody[k]; !ok {
			t.Errorf("body is missing the mandatory field %q", k)
		}
	}
	for _, k := range []string{"source", "prev_hash", "chain_hash"} {
		if _, ok := gotBody[k]; ok {
			t.Errorf("body carries %q, which the pipeline authors -- a source must not assert it", k)
		}
	}
}

// TestPublish_RefusesAnOffContractEnvelopeBeforeSending proves validation is local
// and fail-closed: a violating envelope never reaches the network. Shipping it and
// letting the far side answer 400 would work too, but it would make every contract
// violation look like a transport problem and would depend on the far side staying
// strict -- a server that grew looser must not widen what Control emits.
func TestPublish_RefusesAnOffContractEnvelopeBeforeSending(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mut  func(*ocsf.PublishWire)
	}{
		{"empty-trace-id", func(w *ocsf.PublishWire) { w.TraceID = "" }},
		{"empty-actor-id", func(w *ocsf.PublishWire) { w.ActorID = "" }},
		{"empty-action", func(w *ocsf.PublishWire) { w.Action = "" }},
		{"trace-id-over-bound", func(w *ocsf.PublishWire) { w.TraceID = strings.Repeat("a", 129) }},
		{"actor-id-over-bound", func(w *ocsf.PublishWire) { w.ActorID = strings.Repeat("a", 257) }},
		{"resource-over-bound", func(w *ocsf.PublishWire) { w.Resource = strings.Repeat("a", 1025) }},
		{"outcome-outside-enum", func(w *ocsf.PublishWire) { w.Outcome = "partial" }},
		{"outcome-empty", func(w *ocsf.PublishWire) { w.Outcome = "" }},
		{"payload-absent", func(w *ocsf.PublishWire) { w.Payload = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reached := false
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			wire := validWire()
			tc.mut(&wire)
			err := c.Publish(context.Background(), wire)
			if !errors.Is(err, publish.ErrEnvelope) {
				t.Fatalf("Publish with %s = %v, want ErrEnvelope", tc.name, err)
			}
			if reached {
				t.Errorf("an off-contract envelope reached the ingest; it must be refused locally")
			}
		})
	}
}

// TestNew_RefusesUnusableConfig proves the client fails at CONSTRUCTION, not on the
// first privileged action. A client that cannot publish is a daemon that will deny
// every audited action once traffic starts; that must surface at boot.
func TestNew_RefusesUnusableConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  publish.Config
	}{
		{"no-base-url", publish.Config{ClientCertPath: "c.pem", ClientKeyPath: "k.pem"}},
		{"no-client-identity", publish.Config{BaseURL: "https://audit.internal"}},
		{"key-without-cert", publish.Config{BaseURL: "https://audit.internal", ClientKeyPath: "k.pem"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := publish.New(tc.cfg); !errors.Is(err, publish.ErrConfig) {
				t.Fatalf("New(%s) = %v, want ErrConfig", tc.name, err)
			}
		})
	}
}

// TestNew_CoversTheCertAndCABranches exercises the constructor paths past the
// early field checks: a keypair that fails to load, a CA path that cannot be
// read, a CA file with no usable certificate, and the happy path with a valid
// self-signed keypair (default channel + timeout). These were the uncovered
// branches after the fan-in-injection revival.
func TestNew_CoversTheCertAndCABranches(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	writeSelfSigned(t, certPath, keyPath)

	// A keypair path that does not resolve: LoadX509KeyPair error branch.
	if _, err := publish.New(publish.Config{
		BaseURL: "https://audit.internal", ClientCertPath: "/nope/c.pem", ClientKeyPath: "/nope/k.pem",
	}); !errors.Is(err, publish.ErrConfig) {
		t.Fatal("unloadable keypair did not refuse with ErrConfig")
	}

	// A CA path that cannot be read.
	if _, err := publish.New(publish.Config{
		BaseURL: "https://audit.internal", ClientCertPath: certPath, ClientKeyPath: keyPath,
		CACertPath: "/nope/ca.pem",
	}); !errors.Is(err, publish.ErrConfig) {
		t.Fatal("unreadable CA path did not refuse with ErrConfig")
	}

	// A CA file with no usable certificate.
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := publish.New(publish.Config{
		BaseURL: "https://audit.internal", ClientCertPath: certPath, ClientKeyPath: keyPath,
		CACertPath: badCA,
	}); !errors.Is(err, publish.ErrConfig) {
		t.Fatal("a CA file with no certificate did not refuse with ErrConfig")
	}

	// Happy path: valid keypair + valid CA, default channel and timeout resolved.
	if _, err := publish.New(publish.Config{
		BaseURL: "https://audit.internal/", ClientCertPath: certPath, ClientKeyPath: keyPath,
		CACertPath: certPath, // the self-signed cert is a usable CA PEM
	}); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
}

// writeSelfSigned writes a throwaway self-signed ECDSA cert+key to the given
// paths for the constructor's LoadX509KeyPair to accept.
func writeSelfSigned(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-control-audit-source"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}
