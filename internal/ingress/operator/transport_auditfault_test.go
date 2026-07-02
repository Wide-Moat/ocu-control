// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"errors"
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

// boundOperatorFaultable binds a real operator socket exactly like boundOperator,
// but returns the *audit.RecordingFake driving the killswitch Engine so a test can
// arm an audit-write fault mid-flight and observe how the ROUTE maps it. It exists
// because operatorDepsFor's sink is a local that the standard helper does not
// expose; the audit-first fail-closed property is a route-level contract (the
// engine returning ErrAuditWriteFailed is necessary but not sufficient — the
// handler must map it to a non-2xx deny), so it must be exercised through Serve.
func boundOperatorFaultable(t *testing.T, resolver ingress.IdentityResolver) (*http.Client, *audit.RecordingFake) {
	t.Helper()
	socket := shortSocketPath(t)
	clk := state.SystemClock()
	store := newListerStore(state.NewInMemory(clk))
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{
		ConcurrentSessionsPerTenant: 16,
		CreateRatePerCallerPerMin:   16,
	})
	// The single sink both the lifecycle Manager and the killswitch Engine emit
	// through — the same construction operatorDepsFor uses, but returned so the
	// test can arm the fault.
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
	mcpEng := mcpkey.NewEngine(
		mcpkey.NewMinter(),
		mcpkey.NewInMemRecordStore(),
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
	return client, sink
}

// TestOperatorTransportRevokeAuditFailureDenies is the ROUTE-level pin on the
// audit-first fail-closed invariant for the three kill-switch revoke/resume verbs.
// A privileged operator action must emit its chain-linked OCSF event BEFORE the
// acknowledgement, and the action is DENIED if that audit write fails. The engine
// returns ErrAuditWriteFailed on a faulted sink (proven in the killswitch package),
// but that is only half the contract: the HANDLER must map that error to a non-2xx
// deny rather than swallowing it and writing 200. This drives each verb through the
// real Serve/ServeHTTP with the audit sink armed to fail, and asserts the route
// does NOT acknowledge success.
//
// Without this pin, a handler that dropped the engine error (e.g. `_ = h.RevokeAll(...)`
// then `writeStatus(200)`) — or a writeRevokeError default arm that returned 2xx —
// would ship green: no other operator test drives a privileged route with a faulted
// audit sink over the wire.
func TestOperatorTransportRevokeAuditFailureDenies(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}

	cases := []struct {
		name string
		path string
		body map[string]any
	}{
		{"revoke/one", "/v1alpha/revoke/one", map[string]any{"key": "some-key", "reason": "incident"}},
		{"revoke/all", "/v1alpha/revoke/all", map[string]any{"reason": "incident"}},
		{"resume/all", "/v1alpha/resume/all", map[string]any{"reason": "all-clear"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			client, sink := boundOperatorFaultable(t, resolver)
			// Arm the audit-write fault: every subsequent Emit fails closed with a
			// wrapped ErrAuditWriteFailed and records nothing.
			sink.SetFault(true, errors.New("sink down"))

			code, _ := postJSON(t, client, c.path, c.body)
			if code >= 200 && code < 300 {
				t.Fatalf("%s with a faulted audit sink acknowledged success (%d); a privileged action MUST be denied when the audit write fails (audit-first fail-closed)", c.path, code)
			}
			// The concrete deny status for the audit-fault class is the writeRevokeError
			// default (409). Pin it so a regression that quietly changes the deny code
			// for this class is visible.
			if code != http.StatusConflict {
				t.Fatalf("%s audit-fault deny = %d; want 409 (writeRevokeError default arm)", c.path, code)
			}
		})
	}
}
