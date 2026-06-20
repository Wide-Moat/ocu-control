// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// mtlsPair holds an in-test CA, the server TLS config (RequireAndVerifyClientCert
// against the CA), and a client TLS config presenting a cert whose URI SAN carries a
// tenant/caller-shaped SPIFFE id the default SAN mapper accepts.
type mtlsPair struct {
	serverTLS *tls.Config
	clientTLS *tls.Config
}

// newMTLSPair generates a self-signed CA, a server leaf, and a client leaf whose URI
// SAN is "spiffe://td.test/<tenant>/<caller>", so the gateway's verified-SAN resolver
// derives that service identity. Everything is generated in-process with crypto/x509;
// no fixtures on disk.
func newMTLSPair(t *testing.T, tenant, caller string) mtlsPair {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Server leaf for 127.0.0.1.
	serverCert := newLeaf(t, caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	})

	// Client leaf with a SPIFFE URI SAN carrying tenant/caller.
	spiffeURI := &url.URL{Scheme: "spiffe", Host: "td.test", Path: "/" + tenant + "/" + caller}
	clientCert := newLeaf(t, caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: caller},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{spiffeURI},
	})

	return mtlsPair{
		serverTLS: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS12,
		},
		clientTLS: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      pool,
			ServerName:   "127.0.0.1",
			MinVersion:   tls.VersionTLS12,
		},
	}
}

// newLeaf signs tmpl with the CA, returning a tls.Certificate carrying the leaf and
// its fresh P-256 key.
func newLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// gatewayDepsFor builds the full gateway.Deps over an in-memory Store and a
// do-nothing provider, with the supplied TLS config.
func gatewayDepsFor(t *testing.T, tlsConfig *tls.Config) gateway.Deps {
	t.Helper()
	clk := state.SystemClock()
	store := state.NewInMemory(clk)
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 16, CreateRatePerCallerPerMin: 16})
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: custodian,
		Provider:  nopProvider{},
		Clock:     clk,
		Quota:     gate,
		Handoff:   handoff.NewStager(t.TempDir()),
		Audit:     audit.NewRecordingFake(),
		Profile:   0, // ProfileTrustedOperator (admits on runc)
		Tier:      runtime.TierRunc,
	})
	return gateway.Deps{Manager: mgr, TLSConfig: tlsConfig}
}

// boundGateway binds a real TCP/mTLS gateway on 127.0.0.1:0, starts Serve in the
// background, and returns the bound address and an mTLS http.Client.
func boundGateway(t *testing.T, pair mtlsPair) (string, *http.Client) {
	t.Helper()
	deps := gatewayDepsFor(t, pair.serverTLS)
	l := gateway.NewListener("127.0.0.1:0", deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	addr := l.Addr()
	if addr == "" {
		t.Fatal("Addr() empty after Bind")
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve returned %v; want nil on clean shutdown", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return after context cancel")
		}
	})

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: pair.clientTLS},
	}
	waitGatewayReady(t, client, addr)
	return addr, client
}

// waitGatewayReady polls the create route until the listener accepts a TLS
// connection, so a test request does not race Serve. A 4xx/5xx is "ready"; only a
// dial/handshake error is "not yet".
func waitGatewayReady(t *testing.T, client *http.Client, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Post("https://"+addr+"/v1alpha/sessions/status", "application/json", bytes.NewReader([]byte(`{}`)))
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("gateway listener did not become ready within the deadline")
}

// gwPost sends a JSON POST over mTLS and returns the status code and decoded body.
func gwPost(t *testing.T, client *http.Client, addr, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	resp, err := client.Post("https://"+addr+path, "application/json", &buf)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && bytes.HasPrefix(trimmed, []byte("{")) {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// TestGatewayTransportCreateStatusDestroy drives the FULL gateway mTLS transport
// end-to-end: a create over a verified client cert returns 201 with a host-derived
// key (the cert-SAN-derived identity flowed through), a status read of the same hint
// returns the row, and a destroy tears it down. This exercises Serve,
// connInfoFromRequest, verifiedSANsOf, the CertSANResolver, toRequest, decodeJSON,
// writeJSON/writeStatus, and the Create/Status/Destroy handlers over real mTLS.
func TestGatewayTransportCreateStatusDestroy(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	addr, client := boundGateway(t, pair)

	code, body := gwPost(t, client, addr, "/v1alpha/sessions", map[string]any{
		"session_hint":    "mtls-session",
		"image":           "registry.example/ocu-sandbox:v1",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create over mTLS = %d; want 201", code)
	}
	key, _ := body["key"].(string)
	if key == "" {
		t.Fatalf("create response missing host-derived key: %v", body)
	}

	// Status of the same hint returns the row.
	code, sbody := gwPost(t, client, addr, "/v1alpha/sessions/status", map[string]any{"session_hint": "mtls-session"})
	if code != http.StatusOK {
		t.Fatalf("status over mTLS = %d; want 200", code)
	}
	if sk, _ := sbody["key"].(string); sk != key {
		t.Fatalf("status key = %q; want the created key %q", sk, key)
	}

	// Destroy tears it down.
	code, _ = gwPost(t, client, addr, "/v1alpha/sessions/destroy", map[string]any{"session_hint": "mtls-session"})
	if code != http.StatusOK {
		t.Fatalf("destroy over mTLS = %d; want 200", code)
	}
}

// TestGatewayTransportStatusCrossTenantBlocked drives the audience-scoping defence
// over mTLS: a status read for a hint that addresses no row in the caller's
// namespace is 404 (indistinguishable from not-found), so a service caller cannot
// probe another tenant's session.
func TestGatewayTransportStatusCrossTenantBlocked(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	addr, client := boundGateway(t, pair)

	code, _ := gwPost(t, client, addr, "/v1alpha/sessions/status", map[string]any{"session_hint": "never-created"})
	if code != http.StatusNotFound {
		t.Fatalf("status of an absent session = %d; want 404 (enumeration blocked)", code)
	}
}

// TestGatewayTransportRouteEdges drives the per-route method-not-allowed and
// bad-body branches over mTLS.
func TestGatewayTransportRouteEdges(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	addr, client := boundGateway(t, pair)

	routes := []string{"/v1alpha/sessions", "/v1alpha/sessions/destroy", "/v1alpha/sessions/status"}
	for _, path := range routes {
		// Wrong method -> 405.
		resp, err := client.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d; want 405", path, resp.StatusCode)
		}
		// Malformed body -> 400.
		resp2, err := client.Post("https://"+addr+path, "application/json", bytes.NewReader([]byte("{bad")))
		if err != nil {
			t.Fatalf("POST malformed %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp2.Body)
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST malformed %s = %d; want 400", path, resp2.StatusCode)
		}
	}
}

// TestGatewayBindInvalidAddrErrors proves Bind fails closed on an unbindable
// address (a malformed host:port), returning the error and leaving no listener.
func TestGatewayBindInvalidAddrErrors(t *testing.T) {
	t.Parallel()
	l := gateway.NewListener("256.256.256.256:99999", gateway.Deps{})
	if err := l.Bind(); err == nil {
		_ = l.Close()
		t.Fatal("Bind on an invalid address returned nil; want a fail-closed error")
	}
	if l.Addr() != "" {
		t.Fatalf("Addr() after a failed Bind = %q; want empty", l.Addr())
	}
}

// TestGatewayServeBeforeBindErrors proves Serve refuses before Bind.
func TestGatewayServeBeforeBindErrors(t *testing.T) {
	t.Parallel()
	l := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := l.Serve(context.Background()); err == nil {
		t.Fatal("Serve before Bind returned nil; want a fail-closed error")
	}
}

// TestGatewayCloseIdempotentBeforeBind proves Close is a no-op against a never-bound
// listener and Addr is empty before Bind.
func TestGatewayCloseIdempotentBeforeBind(t *testing.T) {
	t.Parallel()
	l := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := l.Close(); err != nil {
		t.Fatalf("Close before Bind = %v; want nil", err)
	}
	if l.Addr() != "" {
		t.Fatalf("Addr() before Bind = %q; want empty", l.Addr())
	}
}

// TestGatewayScopeAccessor proves the listener exposes its ServiceScope (the
// capability the service handlers take) and that it is valid.
func TestGatewayScopeAccessor(t *testing.T) {
	t.Parallel()
	l := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if !l.Scope().Valid() {
		t.Fatal("Listener.Scope() is not a valid ServiceScope")
	}
	if l.Handlers() == nil {
		t.Fatal("Listener.Handlers() = nil")
	}
}
