// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// argSeamStores are the durable back-ends a bound operator writes through, returned
// so a transport test can re-read the state a route mutated and assert the DURABLE
// effect of the ADDRESSED subject — not merely that the call returned 2xx. This is
// what pins the route->handler argument seam: a route that drops the body's
// load-bearing key/id (passing "" to the handler) still returns 200 for an
// idempotent op, so only re-reading the store for the specific key catches it.
type argSeamStores struct {
	sessions state.Store
	mcpKeys  mcpkey.RecordStore
}

// boundOperatorWithStores binds a real operator socket like boundOperator and
// returns the client plus the durable stores behind it. It mirrors operatorDepsFor
// but keeps the session Store and the mcpkey RecordStore so a test can assert a
// route's durable effect through ServeHTTP.
func boundOperatorWithStores(t *testing.T, resolver ingress.IdentityResolver) (*http.Client, argSeamStores) {
	t.Helper()
	socket := shortSocketPath(t)
	clk := state.SystemClock()
	base := state.NewInMemory(clk)
	store := newListerStore(base)
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{
		ConcurrentSessionsPerTenant: 16,
		CreateRatePerCallerPerMin:   16,
	})
	sink := audit.NewRecordingFake()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     custodian,
		Provider:      nopProvider{},
		Clock:         clk,
		Quota:         gate,
		Handoff:       handoff.NewStager(t.TempDir()),
		Audit:         sink,
		Profile:       0, // ProfileTrustedOperator
		Tier:          ocuruntime.TierRunc,
		AllowedImages: []string{"img", "ocu/sandbox:test", "registry.example/ocu-sandbox:v1"},
		ExecVerifyKey: ingressTestExecVerifyKey(),
	})
	eng := killswitch.NewEngine(store, custodian, nopProvider{}, clk, sink)
	mcpStore := mcpkey.NewInMemRecordStore()
	mcpEng := mcpkey.NewEngine(
		mcpkey.NewMinter(),
		mcpStore,
		func(context.Context) (mcpkey.RenderOutcome, error) { return mcpkey.RenderOutcome{}, nil },
		clk,
		sink,
	)
	deps := operator.Deps{
		Manager:      mgr,
		Engine:       eng,
		MCPKeyEngine: mcpEng,
		Resolver:     resolver,
		Seam:         ingress.NewOperatorSeam(),
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
	// The session Store the routes write through is the base memStore (the lister
	// wrapper only adds a read method and delegates writes), so LoadDeny below reads
	// exactly the deny entries revoke/one authored.
	return client, argSeamStores{sessions: base, mcpKeys: mcpStore}
}

// TestOperatorTransportRevokeOneDeniesTheAddressedKey pins the revoke/one
// route->handler argument seam: the route must pass the body's key through to
// RevokeOne so the DURABLE per-session deny is authored for THAT key. A 200 alone
// proves nothing — RevokeOne is idempotent, so a route that dropped body.Key
// (passing "" to the handler) would still return 200 "revoked" while the addressed
// key stays live. This drives a create then a revoke/one over ServeHTTP and asserts
// the session Store carries a ScopeSession deny for the created key.
func TestOperatorTransportRevokeOneDeniesTheAddressedKey(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	client, stores := boundOperatorWithStores(t, resolver)

	code, body := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "argseam-revoke-one",
		"image":        "img",
	})
	if code != http.StatusCreated {
		t.Fatalf("create = %d; want 201", code)
	}
	key, _ := body["key"].(string)
	if key == "" {
		t.Fatalf("create response missing key: %v", body)
	}

	code, _ = postJSON(t, client, "/v1alpha/revoke/one", map[string]any{"key": key, "reason": "abuse"})
	if code != http.StatusOK {
		t.Fatalf("revoke/one over the wire = %d; want 200", code)
	}

	// The durable effect: a per-session deny for THE ADDRESSED key exists.
	entries, err := stores.sessions.LoadDeny(context.Background())
	if err != nil {
		t.Fatalf("LoadDeny: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Scope == state.ScopeSession && e.Key == key {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("after revoke/one over the wire, no ScopeSession deny for the addressed key %q was authored "+
			"(entries=%v); the route returned 200 but did not revoke the key it was asked to — the body key was "+
			"not passed through to the handler", key, entries)
	}
}

// TestOperatorTransportMCPKeyRevokeRevokesTheAddressedKey pins the mcp-keys/revoke
// route->handler argument seam: the route must pass body.KeyID through to
// MCPKeyRevoke so the ADDRESSED record is flipped to revoked in the store. As with
// revoke/one, a 200 alone proves nothing — the revoke is idempotent, so a route that
// dropped body.KeyID (passing "" to the handler) would still return 200 "revoked"
// while the addressed key stays active. This creates a key over the wire, revokes it
// over the wire, and re-reads the record to assert StatusRevoked.
func TestOperatorTransportMCPKeyRevokeRevokesTheAddressedKey(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	client, stores := boundOperatorWithStores(t, resolver)

	code, body := postJSON(t, client, "/v1alpha/mcp-keys", map[string]any{
		"tenant":     "tenant-x",
		"deployment": "deploy-x",
	})
	if code != http.StatusCreated {
		t.Fatalf("mcp-key create = %d; want 201", code)
	}
	keyID, _ := body["key_id"].(string)
	if keyID == "" {
		t.Fatalf("mcp-key create response missing key_id: %v", body)
	}
	// Precondition: the created record is active in the store.
	before, err := stores.mcpKeys.Get(context.Background(), keyID)
	if err != nil {
		t.Fatalf("mcpKeys.Get before revoke: %v", err)
	}
	if before.Status != mcpkey.StatusActive {
		t.Fatalf("precondition: created record status = %q, want active", before.Status)
	}

	code, _ = postJSON(t, client, "/v1alpha/mcp-keys/revoke", map[string]any{"key_id": keyID, "reason": "rotation"})
	if code != http.StatusOK {
		t.Fatalf("mcp-key revoke over the wire = %d; want 200", code)
	}

	// The durable effect: THE ADDRESSED record is now revoked.
	after, err := stores.mcpKeys.Get(context.Background(), keyID)
	if err != nil {
		t.Fatalf("mcpKeys.Get after revoke: %v", err)
	}
	if after.Status != mcpkey.StatusRevoked {
		t.Errorf("after mcp-keys/revoke over the wire, record %q status = %q, want revoked; the route returned 200 "+
			"but did not revoke the key_id it was asked to — the body key_id was not passed through to the handler", keyID, after.Status)
	}
}

// TestOperatorTransportDestroyAddressesTheBodySession pins the destroy
// route->handler argument seam: the route must pass body.session_hint through to
// Destroy. Destroy of a hint the caller does not own yields ErrNotOwned, which the
// route maps to 404; a create followed by a destroy of the SAME hint succeeds (200),
// while a destroy of a DIFFERENT hint 404s. A route that dropped session_hint
// (passing "" to the handler) would address the wrong (empty) hint, so the destroy
// of the just-created session would no longer succeed — this asserts the addressed
// session is the one destroyed.
func TestOperatorTransportDestroyAddressesTheBodySession(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	client, _ := boundOperatorWithStores(t, resolver)

	const hint = "argseam-destroy"
	code, _ := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": hint,
		"image":        "img",
	})
	if code != http.StatusCreated {
		t.Fatalf("create = %d; want 201", code)
	}

	// Destroying a DIFFERENT hint the caller never created is not-owned -> 404.
	code, _ = postJSON(t, client, "/v1alpha/sessions/destroy", map[string]any{"session_hint": "never-created"})
	if code != http.StatusNotFound {
		t.Fatalf("destroy of an unknown hint = %d; want 404 (not addressable)", code)
	}

	// Destroying the CREATED hint succeeds -> 200. If the route dropped the hint, it
	// would address "" (also not-owned) and this would 404, catching the dropped seam.
	code, _ = postJSON(t, client, "/v1alpha/sessions/destroy", map[string]any{"session_hint": hint})
	if code != http.StatusOK {
		t.Errorf("destroy of the created hint %q over the wire = %d; want 200 — the route must pass the body "+
			"session_hint through to the handler so the ADDRESSED session is the one torn down", hint, code)
	}
}
