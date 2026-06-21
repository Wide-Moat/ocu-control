// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

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

// readEnabledOperator binds an operator listener WITH the admin read-surface
// mounted. It builds the Manager, Engine, and read port over the SAME shared
// store and custodian, so the enriched read enumerates exactly the rows the create
// path wrote. The read port (the custodian) is handed in as Deps.Reader; the
// deployment singletons are set. It returns the client and the custodian.
func readEnabledOperator(t *testing.T, resolver ingress.IdentityResolver, deployment operator.DeploymentInfo) (*http.Client, *registry.Custodian) {
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
		Custodian: custodian,
		Provider:  nopProvider{},
		Clock:     clk,
		Quota:     gate,
		Handoff:   handoff.NewStager(t.TempDir()),
		Audit:     sink,
		Profile:   0,
		Tier:      ocuruntime.TierRunc,
	})
	eng := killswitch.NewEngine(store, custodian, nopProvider{}, clk, sink)
	deps := operator.Deps{
		Manager:    mgr,
		Engine:     eng,
		Resolver:   resolver,
		Seam:       ingress.NewOperatorSeam(),
		Reader:     custodian, // the custodian is the SessionReader (EnrichedLiveSessions)
		Deployment: deployment,
		Healthz:    func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	}

	l := operator.NewListener(socket, deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = l.Serve(ctx) }()
	client := unixClient(socket)
	waitOperatorReady(t, client)
	return client, custodian
}

// TestReadList_LiveSessionsAfterCreate drives a create over the wire, then GETs
// /v1alpha/sessions and asserts the created row appears as a SessionView with the
// lowercase state and a non-zero reserved_at — the end-to-end read path against a
// real bound socket and a real custodian.
func TestReadList_LiveSessionsAfterCreate(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	client, _ := readEnabledOperator(t, resolver, operator.DeploymentInfo{RuntimeTier: "runc", RuntimeProvider: "docker"})

	// Create a session so a live row exists.
	code, _ := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "read-list-1",
		"image":           "ocu/sandbox:test",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d", code)
	}

	// GET the list.
	resp, err := client.Get("http://unix/v1alpha/sessions")
	if err != nil {
		t.Fatalf("GET sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET sessions: want 200, got %d", resp.StatusCode)
	}
	var views []operator.SessionView
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatalf("decode views: %v", err)
	}
	if len(views) == 0 {
		t.Fatalf("want >=1 live session view after create, got 0")
	}
	v := views[0]
	if v.Key == "" {
		t.Errorf("view must carry a host-derived key, got empty")
	}
	if v.State != "active" && v.State != "reserved" {
		t.Errorf("view state must be a lowercase live state, got %q", v.State)
	}
	if v.ReservedAt.IsZero() {
		t.Errorf("view must carry a non-zero reserved_at, got zero")
	}
	if v.Owner.Tenant != "ocu-operator" {
		t.Errorf("view owner tenant: want ocu-operator, got %q", v.Owner.Tenant)
	}
}

// TestReadGet_KeyAndNotFound asserts GET /v1alpha/sessions/{key} returns the row
// for a live key and 404 for an absent one (uniform across released/absent).
func TestReadGet_KeyAndNotFound(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	client, _ := readEnabledOperator(t, resolver, operator.DeploymentInfo{RuntimeTier: "gvisor", RuntimeProvider: "docker"})

	code, _ := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "read-get-1",
		"image":           "ocu/sandbox:test",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d", code)
	}
	// Find the key via the list, then GET it directly.
	resp, _ := client.Get("http://unix/v1alpha/sessions")
	var views []operator.SessionView
	_ = json.NewDecoder(resp.Body).Decode(&views)
	_ = resp.Body.Close()
	if len(views) == 0 {
		t.Fatal("no live views to address")
	}
	key := views[0].Key

	getResp, err := client.Get("http://unix/v1alpha/sessions/" + key)
	if err != nil {
		t.Fatalf("GET by key: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET existing key: want 200, got %d", getResp.StatusCode)
	}
	var one operator.SessionView
	if err := json.NewDecoder(getResp.Body).Decode(&one); err != nil {
		t.Fatalf("decode single view: %v", err)
	}
	if one.Key != key {
		t.Errorf("GET by key returned key %q, want %q", one.Key, key)
	}

	// An absent key is 404.
	missResp, err := client.Get("http://unix/v1alpha/sessions/no-such-key")
	if err != nil {
		t.Fatalf("GET absent key: %v", err)
	}
	_, _ = io.Copy(io.Discard, missResp.Body)
	_ = missResp.Body.Close()
	if missResp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET absent key: want 404, got %d", missResp.StatusCode)
	}
}

// TestReadDeployment returns the deployment-wide singletons.
func TestReadDeployment(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	client, _ := readEnabledOperator(t, resolver, operator.DeploymentInfo{RuntimeTier: "firecracker", RuntimeProvider: "k8s"})

	resp, err := client.Get("http://unix/v1alpha/deployment")
	if err != nil {
		t.Fatalf("GET deployment: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET deployment: want 200, got %d", resp.StatusCode)
	}
	var dv operator.DeploymentView
	if err := json.NewDecoder(resp.Body).Decode(&dv); err != nil {
		t.Fatalf("decode deployment: %v", err)
	}
	if dv.RuntimeTier != "firecracker" || dv.RuntimeProvider != "k8s" {
		t.Errorf("deployment view: want {firecracker,k8s}, got %+v", dv)
	}
}

// TestReadList_UnattestedIs401 asserts an unattested caller is refused before any
// enumeration, exactly as a mutating operator call is.
func TestReadList_UnattestedIs401(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{refuse: true}
	client, _ := readEnabledOperator(t, resolver, operator.DeploymentInfo{RuntimeTier: "runc", RuntimeProvider: "docker"})

	resp, err := client.Get("http://unix/v1alpha/sessions")
	if err != nil {
		t.Fatalf("GET sessions: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unattested GET: want 401, got %d", resp.StatusCode)
	}
}

// TestReadHandlers_HoldNoMutatingCapability is the IMPORT-BOUNDARY structural
// guard (NFR-SEC-26 mirror, ADR-0022): the read handler must not be able to reach
// any mutating operator surface. It holds only the read port, the resolver, and
// the deployment singletons — NOT the OperatorSeam, NOT the lifecycle Manager, NOT
// the kill-switch Engine. This test fails the moment a field of a forbidden type is
// added to ReadHandlers, so the read-only boundary cannot regress unobserved.
func TestReadHandlers_HoldNoMutatingCapability(t *testing.T) {
	rt := reflect.TypeOf(operator.ReadHandlers{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		typeName := f.Type.String()
		// The read handler must carry none of these capability types — each is a
		// path to a mutating operation (mint an OperatorScope, run create/destroy,
		// or author the deny posture / quota override).
		for _, forbidden := range []string{
			"OperatorSeam",
			"lifecycle.Manager",
			"killswitch.Engine",
		} {
			if strings.Contains(typeName, forbidden) {
				t.Errorf("ReadHandlers field %q has forbidden mutating-capability type %s: the read surface must hold no path to a mutating operation",
					f.Name, typeName)
			}
		}
	}
}
