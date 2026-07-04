// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// specRecordingProvider captures every SessionSpec Materialize receives so a
// transport test can assert the wire-decoded mount intent reached the provider
// seam — not merely that the route returned 2xx.
type specRecordingProvider struct {
	mu    sync.Mutex
	specs []ocuruntime.SessionSpec
}

func (p *specRecordingProvider) Materialize(_ context.Context, spec ocuruntime.SessionSpec) (ocuruntime.Sandbox, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.specs = append(p.specs, spec)
	return ocuruntime.Sandbox{}, nil
}
func (p *specRecordingProvider) Teardown() ocuruntime.RuntimeTeardown { return nopTeardown{} }
func (p *specRecordingProvider) Reconcile(context.Context) ([]ocuruntime.Sandbox, error) {
	return nil, nil
}

func (p *specRecordingProvider) captured() []ocuruntime.SessionSpec {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]ocuruntime.SessionSpec, len(p.specs))
	copy(out, p.specs)
	return out
}

// boundGatewayWithProvider binds a real TCP/mTLS gateway like boundGateway but
// wires the supplied provider into the lifecycle Manager, so a transport test can
// observe the SessionSpec the wire-decoded create produced.
func boundGatewayWithProvider(t *testing.T, pair mtlsPair, provider ocuruntime.RuntimeProvider) (string, *http.Client) {
	t.Helper()
	clk := state.SystemClock()
	store := state.NewInMemory(clk)
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 16, CreateRatePerCallerPerMin: 16})
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     custodian,
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       handoff.NewStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       0, // ProfileTrustedOperator (admits on runc)
		Tier:          ocuruntime.TierRunc,
		ExecVerifyKey: ingressTestExecVerifyKey(),
	})
	deps := gateway.Deps{Manager: mgr, TLSConfig: pair.serverTLS}

	l := gateway.NewListener("127.0.0.1:0", deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	addr := l.Addr()
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

// gwPostText sends a JSON POST over mTLS and returns the status code plus the raw
// response body as text, so a test can distinguish the targeted 400 (the
// scope-conflict message) from the generic decode 400.
func gwPostText(t *testing.T, client *http.Client, addr, path string, body any) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode body: %v", err)
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
	return resp.StatusCode, string(raw)
}

// TestGatewayTransportCreateCarriesMountIntent drives a scoped create through the
// REAL mTLS gateway transport and asserts the wire mount_intent (frozen
// session_setup.proto field names) lands on the SessionSpec the provider receives,
// with the AuthToken empty — the F5 wire never carries a credential (custody).
func TestGatewayTransportCreateCarriesMountIntent(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	spy := &specRecordingProvider{}
	addr, client := boundGatewayWithProvider(t, pair, spy)

	code, body := gwPostText(t, client, addr, "/v1alpha/sessions", map[string]any{
		"session_hint": "scoped-mtls",
		"image":        "registry.example/ocu-sandbox:v1",
		"mount_intent": map[string]any{
			"destination":      "/workspace/out",
			"filesystem_id":    "fs-wire-gw",
			"read_only":        false,
			"cache_duration_s": 45,
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("scoped create over mTLS = %d (%s); want 201", code, body)
	}

	specs := spy.captured()
	if len(specs) != 1 || len(specs[0].Mounts) != 1 {
		t.Fatalf("captured specs = %+v; want 1 spec with 1 mount slot", specs)
	}
	want := ocuruntime.MountIntent{
		Destination:  "/workspace/out",
		FilesystemID: "fs-wire-gw",
		CacheSeconds: 45,
	}
	if got := specs[0].Mounts[0]; got != want {
		t.Fatalf("spec.Mounts[0] = %+v; want %+v", got, want)
	}
}

// TestGatewayTransportCreateMountIntentMalformedRefused pins the same wire-level
// validation of a PRESENT mount_intent on the gateway plane (the body type is
// deliberately duplicated per listener, so each plane pins its own copy): scope
// XOR (both AND neither refused), absolute destination, and the 256-char scope-id
// cap — each a targeted 400 with the provider never called.
func TestGatewayTransportCreateMountIntentMalformedRefused(t *testing.T) {
	t.Parallel()
	longID := strings.Repeat("x", 257)
	cases := []struct {
		name    string
		intent  map[string]any
		wantMsg string
	}{
		{
			name: "both scopes named",
			intent: map[string]any{
				"destination":     "/workspace/out",
				"filesystem_id":   "fs-1",
				"memory_store_id": "mem-1",
			},
			wantMsg: "exactly one of filesystem_id / memory_store_id",
		},
		{
			name:    "neither scope named",
			intent:  map[string]any{"destination": "/workspace/out", "read_only": true},
			wantMsg: "exactly one of filesystem_id / memory_store_id",
		},
		{
			name: "relative destination",
			intent: map[string]any{
				"destination":   "workspace/out",
				"filesystem_id": "fs-1",
			},
			wantMsg: "destination must be an absolute guest path",
		},
		{
			name: "filesystem_id over the cap",
			intent: map[string]any{
				"destination":   "/workspace/out",
				"filesystem_id": longID,
			},
			wantMsg: "filesystem_id exceeds 256 characters",
		},
		{
			name: "memory_store_id over the cap",
			intent: map[string]any{
				"destination":     "/workspace/out",
				"memory_store_id": longID,
			},
			wantMsg: "memory_store_id exceeds 256 characters",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pair := newMTLSPair(t, "acme", "worker-7")
			spy := &specRecordingProvider{}
			addr, client := boundGatewayWithProvider(t, pair, spy)

			code, body := gwPostText(t, client, addr, "/v1alpha/sessions", map[string]any{
				"session_hint": "malformed-mtls",
				"image":        "img",
				"mount_intent": tc.intent,
			})
			if code != http.StatusBadRequest {
				t.Fatalf("malformed mount_intent create = %d (%s); want 400", code, body)
			}
			if !strings.Contains(body, tc.wantMsg) {
				t.Fatalf("400 body = %q; want it to contain %q", body, tc.wantMsg)
			}
			if n := len(spy.captured()); n != 0 {
				t.Fatalf("Materialize called %d times on a refused create; want 0", n)
			}
		})
	}
}
