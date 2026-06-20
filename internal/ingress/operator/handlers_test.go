// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestHandlersAccessor proves the Listener exposes its in-process Handlers surface
// for transport-free driving.
func TestHandlersAccessor(t *testing.T) {
	t.Parallel()
	deps := operatorDepsFor(t, operator.NewPeerCredResolver(nil), nil)
	l := operator.NewListener("/unused.sock", deps)
	if l.Handlers() == nil {
		t.Fatal("Listener.Handlers() = nil; want the in-process handler surface")
	}
}

// TestLiftDenyHandler drives the operator denylist-edit handler: an attested caller
// lifts a previously authored per-session deny.
func TestLiftDenyHandler(t *testing.T) {
	t.Parallel()
	h, _, store := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	ctx := context.Background()

	if err := h.RevokeOne(ctx, attestedConn(1001), "session-key", "incident"); err != nil {
		t.Fatalf("RevokeOne: %v", err)
	}
	if err := h.LiftDeny(ctx, attestedConn(1001), "session-key", "false-positive"); err != nil {
		t.Fatalf("LiftDeny: %v", err)
	}
	deny, _ := store.LoadDeny(ctx)
	for _, d := range deny {
		if d.Scope == state.ScopeSession && d.Key == "session-key" {
			t.Fatalf("per-session deny still present after LiftDeny: %v", deny)
		}
	}
}

// TestLiftDenyUnattestedRefused proves LiftDeny refuses an unattested connection
// before any engine call.
func TestLiftDenyUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	if err := h.LiftDeny(context.Background(), unattestedConn(), "k", "x"); err == nil {
		t.Fatal("LiftDeny on an unattested connection returned nil; want a refusal")
	}
}

// TestOverrideQuotaHandler drives the operator quota-override handler: an attested
// caller applies a delta to a counter cell.
func TestOverrideQuotaHandler(t *testing.T) {
	t.Parallel()
	h, _, store := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	ctx := context.Background()
	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: state.Identity{Tenant: "t", Caller: "c"}}

	if err := h.OverrideQuota(ctx, attestedConn(1001), key, 3, 10, "burst"); err != nil {
		t.Fatalf("OverrideQuota: %v", err)
	}
	got, err := store.ReadQuota(ctx, key)
	if err != nil {
		t.Fatalf("ReadQuota: %v", err)
	}
	if got != 3 {
		t.Fatalf("counter after OverrideQuota(+3) = %d; want 3", got)
	}
}

// TestOverrideQuotaUnattestedRefused proves OverrideQuota refuses an unattested
// connection before any engine call.
func TestOverrideQuotaUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: state.Identity{Tenant: "t", Caller: "c"}}
	if err := h.OverrideQuota(context.Background(), unattestedConn(), key, 1, 10, "x"); err == nil {
		t.Fatal("OverrideQuota on an unattested connection returned nil; want a refusal")
	}
}

// TestRevokeAllViaSOARVerifyThenMint drives the SOAR DENY-ALL path: a good signature
// engages the global posture; a bad one is refused with ErrSOARUnverified and
// authors nothing.
func TestRevokeAllViaSOARVerifyThenMint(t *testing.T) {
	t.Parallel()

	// Bad signature: refused, no global deny.
	hBad, _, storeBad := newTestHandlers(t, operator.NewPeerCredResolver(nil), &fakeVerifier{err: killswitch.ErrSOARUnverified})
	if err := hBad.RevokeAllViaSOAR(context.Background(), attestedConn(1001), []byte("p"), []byte("s"), "soar"); !errors.Is(err, killswitch.ErrSOARUnverified) {
		t.Fatalf("RevokeAllViaSOAR with a bad signature = %v; want ErrSOARUnverified", err)
	}
	if deny, _ := storeBad.LoadDeny(context.Background()); len(deny) != 0 {
		t.Fatalf("a SOAR-unverified RevokeAll authored %d deny entries; want 0", len(deny))
	}

	// Good signature: global DENY-ALL engaged.
	hGood, _, storeGood := newTestHandlers(t, operator.NewPeerCredResolver(nil), &fakeVerifier{})
	if err := hGood.RevokeAllViaSOAR(context.Background(), attestedConn(1001), []byte("p"), []byte("s"), "soar"); err != nil {
		t.Fatalf("RevokeAllViaSOAR with a good signature = %v; want nil", err)
	}
	deny, _ := storeGood.LoadDeny(context.Background())
	foundGlobal := false
	for _, d := range deny {
		if d.Scope == state.ScopeGlobal {
			foundGlobal = true
		}
	}
	if !foundGlobal {
		t.Fatalf("RevokeAllViaSOAR (verified) did not engage the global DENY-ALL; entries=%v", deny)
	}
}

// TestRevokeViaSOARNoVerifierConfigured proves the verify-then-mint fail-closed
// default: with no verifier wired, a SOAR revoke is refused exactly as an
// unverifiable signature would be.
func TestRevokeViaSOARNoVerifierConfigured(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil) // nil verifier
	if err := h.RevokeOneViaSOAR(context.Background(), attestedConn(1001), []byte("p"), []byte("s"), "k", "x"); !errors.Is(err, killswitch.ErrSOARUnverified) {
		t.Fatalf("RevokeOneViaSOAR with no verifier = %v; want ErrSOARUnverified (fail-closed)", err)
	}
}

// TestSOARRevokeRecordsPrincipalNotSocketPeer is the load-bearing P2-R2 proof: for a
// SOAR-driven revoke the audit actor (actor.user) MUST be the verified SOAR
// PRINCIPAL, NOT the unix-socket peer that delivered the webhook. The socket is
// attested with one identity (socketPeer) and the verifier surfaces a DISTINCT SOAR
// principal; the emitted audit Record must carry the principal as the actor, so the
// assertion is not vacuous. Both SOAR verbs are exercised.
func TestSOARRevokeRecordsPrincipalNotSocketPeer(t *testing.T) {
	t.Parallel()
	socketPeer := state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}
	principal := state.Identity{Tenant: "soar-tenant", Caller: "soar-principal"}
	if principal == socketPeer {
		t.Fatal("test setup error: the SOAR principal must differ from the socket peer")
	}

	t.Run("revoke_one", func(t *testing.T) {
		t.Parallel()
		h, sink, _ := newTestHandlers(t, fixedResolver{id: socketPeer}, &fakeVerifier{identity: principal})
		if err := h.RevokeOneViaSOAR(context.Background(), attestedConn(1000), []byte("p"), []byte("s"), "session-key", "soar"); err != nil {
			t.Fatalf("RevokeOneViaSOAR (verified) = %v; want nil", err)
		}
		assertActorIsPrincipal(t, sink, audit.ActionRevokeOne, principal, socketPeer)
	})

	t.Run("revoke_all", func(t *testing.T) {
		t.Parallel()
		h, sink, _ := newTestHandlers(t, fixedResolver{id: socketPeer}, &fakeVerifier{identity: principal})
		if err := h.RevokeAllViaSOAR(context.Background(), attestedConn(1000), []byte("p"), []byte("s"), "soar"); err != nil {
			t.Fatalf("RevokeAllViaSOAR (verified) = %v; want nil", err)
		}
		assertActorIsPrincipal(t, sink, audit.ActionRevokeAll, principal, socketPeer)
	})
}

// TestAdminRevokeRecordsSocketPeerAsActor proves the admin/CLI channel's complement
// of the SOAR rule: there the host-attested socket peer IS the operator, so a
// non-SOAR RevokeOne records the socket-peer identity as the audit actor.
func TestAdminRevokeRecordsSocketPeerAsActor(t *testing.T) {
	t.Parallel()
	socketPeer := state.Identity{Tenant: "ocu-operator", Caller: "uid:7777"}
	h, sink, _ := newTestHandlers(t, fixedResolver{id: socketPeer}, nil)
	if err := h.RevokeOne(context.Background(), attestedConn(7777), "session-key", "incident"); err != nil {
		t.Fatalf("RevokeOne = %v; want nil", err)
	}
	rec, ok := recordFor(sink, audit.ActionRevokeOne)
	if !ok {
		t.Fatal("RevokeOne did not emit an ActionRevokeOne record")
	}
	if rec.Caller != socketPeer.Caller || rec.Tenant != socketPeer.Tenant {
		t.Fatalf("admin revoke actor = {%q,%q}, want the socket peer {%q,%q}",
			rec.Tenant, rec.Caller, socketPeer.Tenant, socketPeer.Caller)
	}
}

// assertActorIsPrincipal fails unless the first Record for action carries principal
// as the actor and is NOT the socket peer, the precise P2-R2 invariant.
func assertActorIsPrincipal(t *testing.T, sink *audit.RecordingFake, action audit.Action, principal, socketPeer state.Identity) {
	t.Helper()
	rec, ok := recordFor(sink, action)
	if !ok {
		t.Fatalf("no audit Record for %v after a SOAR revoke", action)
	}
	if rec.Caller != principal.Caller || rec.Tenant != principal.Tenant {
		t.Fatalf("SOAR %v actor = {%q,%q}, want the SOAR principal {%q,%q}",
			action, rec.Tenant, rec.Caller, principal.Tenant, principal.Caller)
	}
	if rec.Caller == socketPeer.Caller && rec.Tenant == socketPeer.Tenant {
		t.Fatalf("SOAR %v actor = the SOCKET PEER %+v; the actor must be the SOAR principal (P2-R2)", action, socketPeer)
	}
}

// recordFor returns the first recorded Record for action and whether one was found.
func recordFor(sink *audit.RecordingFake, action audit.Action) (audit.Record, bool) {
	for _, rec := range sink.Records() {
		if rec.Action == action {
			return rec, true
		}
	}
	return audit.Record{}, false
}

// TestSOARHandlersUnattestedRefused proves both SOAR handlers refuse an unattested
// connection before the verify-then-mint runs.
func TestSOARHandlersUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandlers(t, operator.NewPeerCredResolver(nil), &fakeVerifier{})
	if err := h.RevokeOneViaSOAR(context.Background(), unattestedConn(), nil, nil, "k", "x"); err == nil {
		t.Fatal("RevokeOneViaSOAR on an unattested connection returned nil; want a refusal")
	}
	if err := h.RevokeAllViaSOAR(context.Background(), unattestedConn(), nil, nil, "x"); err == nil {
		t.Fatal("RevokeAllViaSOAR on an unattested connection returned nil; want a refusal")
	}
}

// TestRevokeHandlersUnattestedRefused proves the non-SOAR revoke handlers refuse an
// unattested connection.
func TestRevokeHandlersUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	if err := h.RevokeOne(context.Background(), unattestedConn(), "k", "x"); err == nil {
		t.Fatal("RevokeOne on an unattested connection returned nil; want a refusal")
	}
	if err := h.RevokeAll(context.Background(), unattestedConn(), "x"); err == nil {
		t.Fatal("RevokeAll on an unattested connection returned nil; want a refusal")
	}
}

// TestDestroyHandlerUnattestedRefused proves the Destroy handler refuses an
// unattested connection.
func TestDestroyHandlerUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	if err := h.Destroy(context.Background(), unattestedConn(), "x"); err == nil {
		t.Fatal("Destroy on an unattested connection returned nil; want a refusal")
	}
}
