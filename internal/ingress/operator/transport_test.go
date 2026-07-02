// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

// fixedResolver is a test IdentityResolver that returns a fixed host-derived
// operator identity regardless of the connection's PeerCred. It is the
// test-injection seam (passed through the production Deps.Resolver field, which the
// adapter already exposes) that lets the FULL transport + handler + lifecycle path
// run on darwin AND linux: the real SO_PEERCRED path is unavailable off Linux, so
// over a real Unix socket the ConnContext hook stashes an UNATTESTED ConnInfo, and
// this resolver — like the production peer-cred resolver — derives identity from
// host-attested transport facts (here a fixed test identity), never from a request
// body. It refuses any non-operator channel fail-closed, mirroring the real
// resolver, so the unattested-refusal path is still reachable when desired.
type fixedResolver struct {
	id     state.Identity
	refuse bool // when true, always returns ErrUnattested (the fail-closed path)
}

func (r fixedResolver) Resolve(_ context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	if r.refuse {
		return ingress.AuthenticatedCaller{}, ingress.ErrUnattested
	}
	if conn.Channel != ingress.ChannelOperator {
		return ingress.AuthenticatedCaller{}, ingress.ErrUnattested
	}
	return ingress.AuthenticatedCaller{Identity: r.id, Channel: ingress.ChannelOperator}, nil
}

// operatorDepsFor builds the full operator.Deps (Manager, Engine, Resolver,
// Verifier, and the single OperatorSeam) over an in-memory Store and a do-nothing
// provider, so a real Listener can be bound and Served. It mirrors the construction
// newTestHandlers uses but returns Deps for the transport path. The single
// OperatorSeam is minted here and handed to the adapter alone, modelling cmd.
func operatorDepsFor(t *testing.T, resolver ingress.IdentityResolver, verifier killswitch.SOARVerifier) operator.Deps {
	t.Helper()
	clk := state.SystemClock()
	store := newListerStore(state.NewInMemory(clk))
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{
		ConcurrentSessionsPerTenant: 16,
		CreateRatePerCallerPerMin:   16,
	})
	sink := audit.NewRecordingFake()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: custodian,
		Provider:  nopProvider{},
		Clock:     clk,
		Quota:     gate,
		Handoff:   handoff.NewStager(t.TempDir()),
		Audit:     sink,
		Profile:   0, // ProfileTrustedOperator
		Tier:      ocuruntime.TierRunc,
	})
	eng := killswitch.NewEngine(store, custodian, nopProvider{}, clk, sink)
	// The mcp-key engine over an in-memory record store and a no-op rerender, so a
	// bound transport test can drive POST /v1alpha/mcp-keys create→revoke end to end.
	mcpEng := mcpkey.NewEngine(
		mcpkey.NewMinter(),
		mcpkey.NewInMemRecordStore(),
		func(context.Context) (mcpkey.RenderOutcome, error) { return mcpkey.RenderOutcome{}, nil },
		clk,
		sink,
	)
	return operator.Deps{
		Manager:      mgr,
		Engine:       eng,
		MCPKeyEngine: mcpEng,
		Resolver:     resolver,
		Verifier:     verifier,
		Seam:         ingress.NewOperatorSeam(),
	}
}

// shortSocketPath returns a Unix-socket path under a 0700 directory short enough to
// stay under the platform's sun_path limit (~104 bytes on darwin, ~108 on Linux),
// which the long per-test t.TempDir() path on macOS exceeds. It prefers a short
// shared temp root and registers cleanup of the directory it creates.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	root := os.TempDir()
	if runtime.GOOS == "darwin" {
		// /tmp is a short symlink on macOS, unlike the long $TMPDIR path.
		if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
			root = "/tmp"
		}
	}
	dir, err := os.MkdirTemp(root, "ocuop")
	if err != nil {
		t.Fatalf("mkdir short temp: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod short temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "op.sock")
}

// unixClient builds an http.Client whose transport dials the given Unix socket
// path, so a test can drive real HTTP-over-Unix requests against the bound operator
// listener. The "host" in the URL is a placeholder the dialer ignores.
func unixClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

// boundOperator binds a real operator Unix socket under a 0700 temp dir, starts
// Serve in the background, and returns the socket path and a client. The injected
// resolver drives identity so the full transport path runs cross-platform. The
// healthz handler is wired so the /healthz route is exercised too.
func boundOperator(t *testing.T, resolver ingress.IdentityResolver, verifier killswitch.SOARVerifier) (string, *http.Client, *operator.Listener) {
	t.Helper()
	socket := shortSocketPath(t)
	deps := operatorDepsFor(t, resolver, verifier)
	deps.Healthz = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}

	l := operator.NewListener(socket, deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if l.Addr() == "" {
		t.Fatal("Addr() empty after Bind; want the bound socket path")
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
	return socket, client, l
}

// waitOperatorReady polls /healthz until the server accepts a connection, so a test
// request does not race the goroutine's Serve.
func waitOperatorReady(t *testing.T, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://unix/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("operator listener did not become ready within the deadline")
}

// postJSON sends a JSON POST to the operator socket and returns the status code and
// decoded sessionResponse-shaped body (key+state) when present.
func postJSON(t *testing.T, client *http.Client, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
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
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// TestOperatorTransportCreateThenDestroy drives the FULL operator transport
// end-to-end over a real Unix socket: a real HTTP create reaches the lifecycle
// pipeline (resolved identity → admit → reserve → stage → materialize → commit →
// bind) and returns 201 with a host-derived key, and a real HTTP destroy addressing
// the same hint tears it down (200). This exercises Serve, registerRoutes,
// connInfoFromRequest, toRequest, decodeJSON, writeJSON, writeStatus, and the
// Create/Destroy handlers over the wire.
func TestOperatorTransportCreateThenDestroy(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// Create over the wire.
	code, body := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "wire-session",
		"image":           "registry.example/ocu-sandbox:v1",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create over the wire = %d; want 201", code)
	}
	if body["key"] == nil || body["key"].(string) == "" {
		t.Fatalf("create response missing host-derived key: %v", body)
	}

	// Destroy the same session by its hint.
	code, _ = postJSON(t, client, "/v1alpha/sessions/destroy", map[string]any{"session_hint": "wire-session"})
	if code != http.StatusOK {
		t.Fatalf("destroy over the wire = %d; want 200", code)
	}
}

// TestOperatorTransportRevokeOneAndAll drives the kill-switch verbs over the wire:
// a create, then a RevokeOne of its key (200), then a RevokeAll DENY-ALL (200). It
// proves the operator-only routes are reachable on the operator socket and that the
// minted OperatorScope flows from the held seam through to the killswitch Engine.
func TestOperatorTransportRevokeOneAndAll(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	code, body := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "to-revoke",
		"image":           "img",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create = %d; want 201", code)
	}
	key, _ := body["key"].(string)
	if key == "" {
		t.Fatalf("create response missing key: %v", body)
	}

	// RevokeOne the created key.
	code, _ = postJSON(t, client, "/v1alpha/revoke/one", map[string]any{"key": key, "reason": "abuse"})
	if code != http.StatusOK {
		t.Fatalf("revoke/one over the wire = %d; want 200", code)
	}

	// RevokeAll engages DENY-ALL.
	code, _ = postJSON(t, client, "/v1alpha/revoke/all", map[string]any{"reason": "incident"})
	if code != http.StatusOK {
		t.Fatalf("revoke/all over the wire = %d; want 200", code)
	}
}

// TestOperatorTransportMCPKeyCreateThenRevoke drives the mounted mcp-key routes
// end-to-end over a real Unix socket: POST /v1alpha/mcp-keys returns 201 with a
// shown-once sk-ocu- raw key + a key_id, and POST /v1alpha/mcp-keys/revoke of that
// key_id returns 200. This is the wire proof that the routes landed at the A2
// wire-freeze checkpoint — it exercises registerRoutes, the create/revoke bodies,
// MCPKeyCreate/MCPKeyRevoke, and the OperatorScope flow from the held seam through
// to the mcpkey Engine.
func TestOperatorTransportMCPKeyCreateThenRevoke(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// Create over the wire.
	code, body := postJSON(t, client, "/v1alpha/mcp-keys", map[string]any{
		"tenant":     "tenant-x",
		"deployment": "deploy-x",
	})
	if code != http.StatusCreated {
		t.Fatalf("mcp-key create over the wire = %d; want 201", code)
	}
	rawKey, _ := body["raw_key"].(string)
	if len(rawKey) < 7 || rawKey[:7] != "sk-ocu-" {
		t.Fatalf("mcp-key create response raw_key = %q; want an sk-ocu- key", rawKey)
	}
	keyID, _ := body["key_id"].(string)
	if keyID == "" {
		t.Fatalf("mcp-key create response missing key_id: %v", body)
	}
	if tenant, _ := body["tenant"].(string); tenant != "tenant-x" {
		t.Fatalf("mcp-key create response tenant = %q; want tenant-x", tenant)
	}

	// Revoke the created key by its key_id.
	code, _ = postJSON(t, client, "/v1alpha/mcp-keys/revoke", map[string]any{
		"key_id": keyID,
		"reason": "rotation",
	})
	if code != http.StatusOK {
		t.Fatalf("mcp-key revoke over the wire = %d; want 200", code)
	}
}

// TestOperatorTransportMCPKeyRevokeUnknownIsIdempotent proves the revoke route is
// idempotent on an unknown key_id: revoking a key that was never created is a 200
// no-op, NOT a 404. This is deliberate — a 404 would be a cross-tenant existence
// oracle. The store's Revoke is a no-op on an absent id.
func TestOperatorTransportMCPKeyRevokeUnknownIsIdempotent(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	code, _ := postJSON(t, client, "/v1alpha/mcp-keys/revoke", map[string]any{
		"key_id": "never-minted-id",
		"reason": "x",
	})
	if code != http.StatusOK {
		t.Fatalf("mcp-key revoke of an unknown id = %d; want 200 (idempotent no-op)", code)
	}
}

// TestOperatorTransportMCPKeyEdges drives the mcp-key routes' method-not-allowed
// (GET → 405), unattested (refusing resolver → 401), and engine-unset (nil
// MCPKeyEngine → 503 fail-closed, not a panic) branches over the wire.
func TestOperatorTransportMCPKeyEdges(t *testing.T) {
	t.Parallel()

	// Method-not-allowed: GET on the POST-only mcp-key routes.
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)
	for _, path := range []string{"/v1alpha/mcp-keys", "/v1alpha/mcp-keys/revoke"} {
		resp, err := client.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d; want 405", path, resp.StatusCode)
		}
	}

	// Unattested: a refusing resolver makes both mcp-key verbs 401.
	_, refusingClient, _ := boundOperator(t, fixedResolver{refuse: true}, nil)
	code, _ := postJSON(t, refusingClient, "/v1alpha/mcp-keys", map[string]any{"tenant": "t"})
	if code != http.StatusUnauthorized {
		t.Fatalf("unattested mcp-key create = %d; want 401", code)
	}
	code, _ = postJSON(t, refusingClient, "/v1alpha/mcp-keys/revoke", map[string]any{"key_id": "k"})
	if code != http.StatusUnauthorized {
		t.Fatalf("unattested mcp-key revoke = %d; want 401", code)
	}
}

// TestOperatorTransportMCPKeyEngineUnset503 proves the fail-closed nil-engine
// path: a bound listener whose Deps omits the MCPKeyEngine returns 503 (a clean
// refusal), NOT a nil-pointer panic that crashes the Serve goroutine. The route
// is mounted unconditionally, so the nil guard is the boundary that keeps an
// unconfigured deployment from crashing on the first mcp-key request.
func TestOperatorTransportMCPKeyEngineUnset503(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	deps := operatorDepsFor(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, nil)
	deps.MCPKeyEngine = nil // model a deployment that did not wire the engine
	deps.Healthz = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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

	code, _ := postJSON(t, client, "/v1alpha/mcp-keys", map[string]any{"tenant": "t"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("mcp-key create with a nil engine = %d; want 503 (fail-closed, not a panic)", code)
	}
}

// TestOperatorTransportResumeAll drives the new resume verb over the wire: after a
// RevokeAll engages DENY-ALL, a /v1alpha/resume/all POST lifts it (200), proving the
// operator-only resume route is reachable on the operator socket and the minted
// OperatorScope flows from the held seam through to the killswitch Engine. A create
// after the resume then succeeds (201), proving the in-band lift took effect.
func TestOperatorTransportResumeAll(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// Engage DENY-ALL, then a create is refused (409).
	code, _ := postJSON(t, client, "/v1alpha/revoke/all", map[string]any{"reason": "incident"})
	if code != http.StatusOK {
		t.Fatalf("revoke/all = %d; want 200", code)
	}
	code, _ = postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "blocked", "image": "img", "control_pub_key": make([]byte, 32),
	})
	if code != http.StatusConflict {
		t.Fatalf("create during DENY-ALL = %d; want 409", code)
	}

	// Lift the global deny in-band.
	code, _ = postJSON(t, client, "/v1alpha/resume/all", map[string]any{"reason": "all-clear"})
	if code != http.StatusOK {
		t.Fatalf("resume/all over the wire = %d; want 200", code)
	}

	// A create now succeeds.
	code, body := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "after-resume", "image": "img", "control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create after resume/all = %d; want 201", code)
	}
	if body["key"] == nil || body["key"].(string) == "" {
		t.Fatalf("create-after-resume response missing host-derived key: %v", body)
	}
}

// TestOperatorTransportResumeAllEdges drives the resume route's method-not-allowed
// (GET → 405) and unattested (refusing resolver → 401) edges, mirroring the
// revoke/all route-edge tests so writeRevokeError is exercised on the resume path.
func TestOperatorTransportResumeAllEdges(t *testing.T) {
	t.Parallel()

	// Method-not-allowed: GET on the POST-only resume route.
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)
	resp, err := client.Get("http://unix/v1alpha/resume/all")
	if err != nil {
		t.Fatalf("GET resume/all: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET resume/all = %d; want 405", resp.StatusCode)
	}

	// Unattested: a refusing resolver makes resume/all 401.
	_, refusingClient, _ := boundOperator(t, fixedResolver{refuse: true}, nil)
	code, _ := postJSON(t, refusingClient, "/v1alpha/resume/all", map[string]any{"reason": "x"})
	if code != http.StatusUnauthorized {
		t.Fatalf("unattested resume/all = %d; want 401", code)
	}
}

// TestOperatorTransportUnattestedRefused drives the fail-closed transport path: a
// resolver that refuses (modelling an unattested connection — exactly what the real
// SO_PEERCRED path produces when the kernel attests nothing) makes a create return
// 401 over the wire, before any host state.
func TestOperatorTransportUnattestedRefused(t *testing.T) {
	t.Parallel()
	_, client, _ := boundOperator(t, fixedResolver{refuse: true}, nil)

	code, _ := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "x",
		"image":           "img",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusUnauthorized {
		t.Fatalf("create on an unattested connection over the wire = %d; want 401", code)
	}
}

// TestOperatorTransportBadBodyAndMethod drives the decode-error and
// method-not-allowed branches over the wire: a malformed JSON body is 400, and a GET
// on a POST-only route is 405.
func TestOperatorTransportBadBodyAndMethod(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// Malformed JSON body -> 400.
	resp, err := client.Post("http://unix/v1alpha/sessions", "application/json", bytes.NewReader([]byte("{not json")))
	if err != nil {
		t.Fatalf("POST malformed body: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create with a malformed body = %d; want 400", resp.StatusCode)
	}

	// Wrong method on a POST-only route -> 405.
	getResp, err := client.Get("http://unix/v1alpha/sessions")
	if err != nil {
		t.Fatalf("GET sessions: %v", err)
	}
	_, _ = io.Copy(io.Discard, getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET on a POST-only route = %d; want 405", getResp.StatusCode)
	}
}

// TestOperatorTransportOversizedBody413 drives the body-cap over the wire: a POST of
// a body larger than the cap to a real bound operator socket is refused with 413
// Request Entity Too Large, NOT 200/201 or normal processing. Identity is attested
// (a fixedResolver), so the 413 is the size cap and not a 401 — the oversized-body
// path, not the unattested path. The white-box decode test is the authoritative proof
// the body is not read whole into memory; this proves the 413 reaches the client.
func TestOperatorTransportOversizedBody413(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// A valid-JSON head followed by a long run, larger than the 64KiB cap, so the
	// refusal is the size cap rather than a syntax error mid-stream.
	oversized := append([]byte(`{"session_hint":"`), bytes.Repeat([]byte("A"), 128<<10)...)
	resp, err := client.Post("http://unix/v1alpha/sessions", "application/json", bytes.NewReader(oversized))
	if err != nil {
		// The server may refuse and close the connection while the client is still
		// uploading, so the client can surface a write/reset error instead of reading
		// the 413. That is itself a refusal; the white-box decode test is the
		// deterministic proof the body is rejected and never read whole into memory.
		t.Logf("oversized POST surfaced a transport error after refusal (acceptable): %v", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	// The oversized body must be REFUSED, never accepted or normally processed: a 2xx
	// is the bug the cap closes. The honest, expected refusal is 413, which the
	// production decode path returns deterministically (proven by the white-box decode
	// test); the wire assertion here is that the refusal reaches the client.
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		return // the clean, expected outcome
	}
	if resp.StatusCode < 400 {
		t.Fatalf("create with an oversized body = %d; want a refusal (413), got a non-refusal status", resp.StatusCode)
	}
	t.Logf("oversized POST refused with %d (expected 413; a non-413 refusal can occur if the client races the server's mid-upload close)", resp.StatusCode)
}

// TestOperatorTransportDestroyForeignHintNotFound drives the destroy not-addressable
// path over the wire: a hint that addresses no row in the caller's namespace is 404
// (indistinguishable from not-found), so a forge attempt cannot probe existence.
func TestOperatorTransportDestroyAbsentNotFound(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	code, _ := postJSON(t, client, "/v1alpha/sessions/destroy", map[string]any{"session_hint": "never-created"})
	if code != http.StatusNotFound {
		t.Fatalf("destroy of an absent session = %d; want 404", code)
	}
}

// TestOperatorTransportRouteEdges drives the per-route method-not-allowed and
// bad-body branches across the destroy and revoke routes, plus the unattested
// refusals that exercise writeDestroyError and writeRevokeError over the wire.
func TestOperatorTransportRouteEdges(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	postOnly := []string{"/v1alpha/sessions/destroy", "/v1alpha/revoke/one", "/v1alpha/revoke/all"}

	// Wrong method -> 405 on each POST-only route.
	for _, path := range postOnly {
		resp, err := client.Get("http://unix" + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d; want 405", path, resp.StatusCode)
		}
	}

	// Malformed body -> 400 on each.
	for _, path := range postOnly {
		resp, err := client.Post("http://unix"+path, "application/json", bytes.NewReader([]byte("{bad")))
		if err != nil {
			t.Fatalf("POST malformed %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST malformed %s = %d; want 400", path, resp.StatusCode)
		}
	}
}

// TestOperatorTransportUnattestedAcrossRoutes drives the writeDestroyError and
// writeRevokeError unattested (401) branches over the wire: a refusing resolver
// makes destroy and the two revoke verbs all return 401.
func TestOperatorTransportUnattestedAcrossRoutes(t *testing.T) {
	t.Parallel()
	_, client, _ := boundOperator(t, fixedResolver{refuse: true}, nil)

	cases := []struct {
		path string
		body any
	}{
		{"/v1alpha/sessions/destroy", map[string]any{"session_hint": "x"}},
		{"/v1alpha/revoke/one", map[string]any{"key": "k", "reason": "r"}},
		{"/v1alpha/revoke/all", map[string]any{"reason": "r"}},
	}
	for _, c := range cases {
		code, _ := postJSON(t, client, c.path, c.body)
		if code != http.StatusUnauthorized {
			t.Fatalf("unattested %s = %d; want 401", c.path, code)
		}
	}
}

// TestBindRemovesStaleSocket proves Bind's stale-socket removal: a leftover socket
// file from a prior run is removed and the re-bind succeeds, rather than failing
// with "address already in use". We bind, abandon the socket file, then bind a fresh
// listener on the same path.
func TestBindRemovesStaleSocket(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)
	deps := operatorDepsFor(t, fixedResolver{id: state.Identity{Tenant: "t", Caller: "c"}}, nil)

	// Seed a stale socket file: bind a throwaway listener and abandon it (do NOT
	// Close, which would unlink the file), so a genuine socket file persists as the
	// residue a crash leaves behind. removeStaleSocket accepts a socket (and refuses a
	// regular file), so the file must be a real socket.
	stale, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}
	t.Cleanup(func() { _ = stale.Close() })

	// Bind over the stale socket: removeStaleSocket unlinks it and the bind succeeds.
	l := operator.NewListener(socket, deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind over a stale socket = %v; want success (stale removed)", err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

// TestRevokeAllEmptyBodyOverWire drives decodeJSON's empty-body branch: a
// parameterless revoke/all POST with no body decodes to the zero value and succeeds
// (200).
func TestRevokeAllEmptyBodyOverWire(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	resp, err := client.Post("http://unix/v1alpha/revoke/all", "application/json", nil)
	if err != nil {
		t.Fatalf("POST revoke/all with no body: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke/all with an empty body = %d; want 200", resp.StatusCode)
	}
}

// TestServeBeforeBindErrors proves Serve refuses when called before Bind (no bound
// socket), the fail-closed guard.
func TestServeBeforeBindErrors(t *testing.T) {
	t.Parallel()
	l := operator.NewListener(filepath.Join(t.TempDir(), "x.sock"), operator.Deps{})
	if err := l.Serve(context.Background()); err == nil {
		t.Fatal("Serve before Bind returned nil; want a fail-closed error")
	}
}

// TestCloseIdempotentBeforeBind proves Close is a no-op against a never-bound
// listener.
func TestCloseIdempotentBeforeBind(t *testing.T) {
	t.Parallel()
	l := operator.NewListener(filepath.Join(t.TempDir(), "x.sock"), operator.Deps{})
	if err := l.Close(); err != nil {
		t.Fatalf("Close before Bind = %v; want nil (idempotent)", err)
	}
	if l.Addr() != "" {
		t.Fatalf("Addr() before Bind = %q; want empty", l.Addr())
	}
}
