// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

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
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// specRecordingProvider captures every SessionSpec Materialize receives so a
// transport test can assert the wire-decoded mount intent reached the provider
// seam — not merely that the route returned 2xx. A route that drops or zeroes
// the body's mount_intent still creates a session, so only the captured spec
// catches the seam cut.
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

// boundOperatorWithProvider binds a real operator socket like boundOperator but
// wires the supplied provider into the lifecycle Manager, so a transport test
// can observe the SessionSpec the wire-decoded create produced.
func boundOperatorWithProvider(t *testing.T, resolver ingress.IdentityResolver, provider ocuruntime.RuntimeProvider) *http.Client {
	t.Helper()
	socket := shortSocketPath(t)
	clk := state.SystemClock()
	store := newListerStore(state.NewInMemory(clk))
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{
		ConcurrentSessionsPerTenant: 16,
		CreateRatePerCallerPerMin:   16,
	})
	sink := audit.NewRecordingFake()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     custodian,
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       handoff.NewStager(t.TempDir()),
		Audit:         sink,
		Profile:       0, // ProfileTrustedOperator
		Tier:          ocuruntime.TierRunc,
		AllowedImages: []string{"img", "ocu/sandbox:test", "registry.example/ocu-sandbox:v1"},
		ExecVerifyKey: ingressTestExecVerifyKey(),
	})
	eng := killswitch.NewEngine(store, custodian, provider, clk, sink, gate)
	deps := operator.Deps{
		Manager:  mgr,
		Engine:   eng,
		Resolver: resolver,
		Seam:     ingress.NewOperatorSeam(),
		Healthz: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		},
	}

	l := operator.NewListener(socket, deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
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
	client := unixClient(socket)
	waitOperatorReady(t, client)
	return client
}

// postForText sends a JSON POST and returns the status code plus the raw response
// body as text, so a test can distinguish the targeted 400 (the scope-conflict
// message) from the generic decode 400.
func postForText(t *testing.T, client *http.Client, path string, body any) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode body: %v", err)
	}
	resp, err := client.Post("http://unix"+path, "application/json", &buf)
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

// TestOperatorTransportCreateCarriesMountIntent drives a scoped create through the
// REAL bound operator socket and asserts the wire mount_intent lands on the
// SessionSpec the provider receives: the wire body (frozen session_setup.proto
// field names) is the only source of the storage scope, and the AuthToken stays
// empty — the wire NEVER carries a credential (custody; NFR-SEC-43 keeps identity
// host-derived while the mount fields ride as intents).
func TestOperatorTransportCreateCarriesMountIntent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		intent map[string]any
		want   ocuruntime.MountIntent
	}{
		{
			name: "filesystem scope",
			intent: map[string]any{
				"destination":      "/workspace/out",
				"filesystem_id":    "fs-wire-01",
				"read_only":        false,
				"cache_duration_s": 45,
			},
			want: ocuruntime.MountIntent{
				Destination:  "/workspace/out",
				FilesystemID: "fs-wire-01",
				CacheSeconds: 45,
			},
		},
		{
			name: "memory-store scope read-only",
			intent: map[string]any{
				"destination":      "/workspace/in",
				"memory_store_id":  "mem-wire-01",
				"read_only":        true,
				"cache_duration_s": 5,
			},
			want: ocuruntime.MountIntent{
				Destination:   "/workspace/in",
				MemoryStoreID: "mem-wire-01",
				ReadOnly:      true,
				CacheSeconds:  5,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spy := &specRecordingProvider{}
			client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

			code, body := postForText(t, client, "/v1alpha/sessions", map[string]any{
				"session_hint": "scoped-session",
				"image":        "registry.example/ocu-sandbox:v1",
				"mount_intent": tc.intent,
			})
			if code != http.StatusCreated {
				t.Fatalf("scoped create over the wire = %d (%s); want 201", code, body)
			}

			specs := spy.captured()
			if len(specs) != 1 {
				t.Fatalf("Materialize called %d times; want 1", len(specs))
			}
			if len(specs[0].Mounts) != 1 {
				t.Fatalf("spec.Mounts = %d entries; want 1", len(specs[0].Mounts))
			}
			got := specs[0].Mounts[0]
			if got != tc.want {
				t.Fatalf("spec.Mounts[0] = %+v; want %+v", got, tc.want)
			}
			if got.AuthToken != "" {
				t.Fatalf("spec.Mounts[0].AuthToken = %q; the wire must never carry a credential", got.AuthToken)
			}
		})
	}
}

// TestOperatorTransportCreateMountIntentMalformedRefused pins the wire-level
// validation of a PRESENT mount_intent to the published contract shape: exactly
// one of filesystem_id / memory_store_id (both AND neither refused), an absolute
// destination, and the 256-char scope-id cap. Every refusal is 400 at decode with
// its targeted message, BEFORE any host state — the provider is never called. The
// message assertions distinguish these refusals from the generic unknown-field
// 400 the route returned before mount_intent existed.
func TestOperatorTransportCreateMountIntentMalformedRefused(t *testing.T) {
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
			spy := &specRecordingProvider{}
			client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

			code, body := postForText(t, client, "/v1alpha/sessions", map[string]any{
				"session_hint": "malformed",
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

// TestOperatorTransportCreateMountIntentAuthTokenRefused pins custody on the wire:
// a mount_intent smuggling an auth_token field is refused 400 (strict decode), and
// the provider is never called. The Storage-JWT rides the host-side F7 push only —
// no create body carries a credential.
func TestOperatorTransportCreateMountIntentAuthTokenRefused(t *testing.T) {
	t.Parallel()
	spy := &specRecordingProvider{}
	client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

	code, _ := postForText(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "smuggler",
		"image":        "img",
		"mount_intent": map[string]any{
			"destination":   "/workspace/out",
			"filesystem_id": "fs-1",
			"auth_token":    "eyJ.fake.token",
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("auth_token-in-mount_intent create = %d; want 400", code)
	}
	if n := len(spy.captured()); n != 0 {
		t.Fatalf("Materialize called %d times on a refused create; want 0", n)
	}
}

// TestOperatorTransportCreateBareBodyStaysNoScope pins the ADR-0017 no-scope path:
// a create WITHOUT mount_intent still lands 201 and the provider sees a zero
// MountIntent — the exec lifecycle stays decoupled from the storage leg.
func TestOperatorTransportCreateBareBodyStaysNoScope(t *testing.T) {
	t.Parallel()
	spy := &specRecordingProvider{}
	client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

	code, body := postForText(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "bare-session",
		"image":        "img",
	})
	if code != http.StatusCreated {
		t.Fatalf("bare create = %d (%s); want 201", code, body)
	}
	specs := spy.captured()
	if len(specs) != 1 || len(specs[0].Mounts) != 1 {
		t.Fatalf("bare create specs = %+v; want 1 spec with 1 mount slot", specs)
	}
	if got := specs[0].Mounts[0]; got != (ocuruntime.MountIntent{}) {
		t.Fatalf("bare create spec.Mounts[0] = %+v; want the zero MountIntent", got)
	}
}
