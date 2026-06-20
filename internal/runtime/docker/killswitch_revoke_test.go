// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// This test lives in package docker, NOT package killswitch, on purpose. Driving
// the kill-switch emergency revoke END-TO-END through the REAL below-seam finalizer
// step-1 requires a real docker.Provider built on the unexported fake-SDK harness
// (newFakeAPI / fakeAPI), which is not importable from the killswitch test package.
// The killswitch package's own tests use an in-package recordingProvider whose
// ForceKill is a no-op counter — it never runs the finalizer, so it CANNOT prove a
// revoke (it is green with or without the Egress fix). To prove the fix is
// non-vacuous the test must exercise the killswitch.Engine against a provider whose
// Teardown().ForceKill executes the real finalizer against a SHARED *cred.Revoker —
// which is only possible here. The cross-package call still attributes coverage to
// killswitch.forceKillRow.

// ksRevokeStart anchors the FakeClock the Revoker stamps its monotonic dead marks
// from, so the wall-setback assertion is reproducible.
var ksRevokeStart = time.Date(2025, time.May, 2, 3, 4, 5, 0, time.UTC)

// ksOwner is the host-derived identity the reserved-row fixture is written under;
// the reservation key derived from it IS the row.Key the create-path mint records
// the jti against (NFR-SEC-43).
var ksOwner = state.Identity{Tenant: "tenant-ks", Caller: "caller-ks"}

// ksOperator is the host-attested operator identity stamped onto the OperatorScope
// at mint, distinct from the row owner so the audit-actor assertion is not vacuous.
var ksOperator = state.Identity{Tenant: "ocu-operator", Caller: "uid:2000"}

// ksRevokeHarness bundles a killswitch.Engine driven through a REAL docker.Provider
// (the fake-SDK API + a shared *cred.Revoker), so a force-kill runs the real
// finalizer step-1 revoke against the shared index.
type ksRevokeHarness struct {
	engine  *killswitch.Engine
	cust    *registry.Custodian
	store   state.Store
	revoker *cred.Revoker
	clk     *state.FakeClock
	audit   *audit.RecordingFake
	scope   ingress.OperatorScope
}

func newKSRevokeHarness(t *testing.T) *ksRevokeHarness {
	t.Helper()
	clk := state.NewFakeClock(ksRevokeStart)
	revoker := cred.NewRevoker(clk)

	// The REAL Docker provider over the fake SDK, sharing the one Revoker the
	// create-path mint records against and the finalizer revokes from. This is the
	// same wiring lifecycle.Destroy's revoke path uses; here it is reached through
	// the kill-switch emergency path.
	provider, err := NewDockerProvider(runtime.TierRunc, Deps{API: newFakeAPI(), Revoker: revoker})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}

	// The in-memory Store already implements LiveLister, so the Custodian's
	// ReservedAndActiveKeys enumerate (RevokeAll's force-kill-every step) lights up
	// with no wrapper.
	store := state.NewInMemory(clk)
	cust := registry.NewCustodian(store)
	sink := audit.NewRecordingFake()
	engine := killswitch.NewEngine(store, cust, provider, clk, sink)
	scope := ingress.NewOperatorSeam().Mint(ksOperator)

	return &ksRevokeHarness{
		engine:  engine,
		cust:    cust,
		store:   store,
		revoker: revoker,
		clk:     clk,
		audit:   sink,
		scope:   scope,
	}
}

// seedLiveSession reserves a RESERVED row under ksOwner and records a jti against
// the row.Key exactly as the create-path mint does (signer Record(SessionKey, jti)
// where SessionKey == row.Key). It returns the row.Key string and the jti so the
// caller can assert IsRevoked(jti) after the emergency revoke.
func (h *ksRevokeHarness) seedLiveSession(t *testing.T, handle, jti string) (string, string) {
	t.Helper()
	key := registry.DeriveKey(ksOwner, handle)
	if _, err := h.cust.Reserve(context.Background(), key, ksOwner); err != nil {
		t.Fatalf("seed reserve %q: %v", handle, err)
	}
	rowKey := key.String()
	// Bind the jti to the host-derived session key, the SAME key signer.go:262
	// records under (req.SessionKey == row.Key). This is the recorded mint the
	// emergency revoke must mark dead.
	h.revoker.Record(rowKey, jti)
	if h.revoker.IsRevoked(jti) {
		t.Fatalf("freshly recorded jti %q must not be revoked before the emergency revoke", jti)
	}
	return rowKey, jti
}

// TestKillswitchRevokeOneRevokesRecordedJTI proves the NFR-SEC-01 fix on the
// RevokeOne reach: the operator single-session emergency revoke, routed
// RevokeOne -> forceKillKey -> forceKillRow, marks the recorded jti dead. This is
// RED before the forceKillRow Egress fix (zero Egress -> FilesystemID=="" ->
// ErrRevokeUnbound -> the jti stays live) and GREEN after it.
func TestKillswitchRevokeOneRevokesRecordedJTI(t *testing.T) {
	t.Parallel()
	h := newKSRevokeHarness(t)
	ctx := context.Background()

	rowKey, jti := h.seedLiveSession(t, "revoke-one-target", "jti-revoke-one")

	if err := h.engine.RevokeOne(ctx, h.scope, rowKey, "incident-one"); err != nil {
		t.Fatalf("RevokeOne: %v", err)
	}

	// THE LOAD-BEARING ASSERTION: after the emergency revoke ran, the recorded jti
	// must be revoked. RED without the forceKillRow Egress fix.
	if !h.revoker.IsRevoked(jti) {
		t.Fatal("after the emergency revoke ran, the recorded jti must be revoked (RevokeOne, NFR-SEC-01)")
	}

	// Audit-first ordering preserved: exactly one revoke_one record carrying the
	// operator identity as the actor (the fix is purely the Sandbox.Egress field and
	// must not disturb the audit emit).
	recs := h.audit.Records()
	if len(recs) != 1 || recs[0].Action != audit.ActionRevokeOne {
		t.Fatalf("audit records = %+v, want exactly one revoke_one", recs)
	}
	if recs[0].Caller != ksOperator.Caller || recs[0].Tenant != ksOperator.Tenant {
		t.Fatalf("revoke_one actor = {%q,%q}, want the operator {%q,%q}",
			recs[0].Tenant, recs[0].Caller, ksOperator.Tenant, ksOperator.Caller)
	}

	// A wall-clock setback after the revoke never un-revokes it (NFR-SEC-48): the
	// fix did not disturb the dead-mark monotonicity.
	h.clk.SetWallClock(ksRevokeStart.Add(-72 * time.Hour))
	if !h.revoker.IsRevoked(jti) {
		t.Fatal("a wall-clock setback must never un-revoke a dead jti")
	}
}

// TestKillswitchRevokeAllRevokesRecordedJTI proves the NFR-SEC-01 fix on the
// RevokeAll reach: the deployment-wide DENY-ALL force-kills every live row, routed
// RevokeAll -> the sweep loop -> forceKillRow, marking the recorded jti dead. Both
// reaches share the one forceKillRow builder, so the single Egress edit fixes both;
// this exercises the RevokeAll route distinctly. RED before the fix, GREEN after.
func TestKillswitchRevokeAllRevokesRecordedJTI(t *testing.T) {
	t.Parallel()
	h := newKSRevokeHarness(t)
	ctx := context.Background()

	_, jti := h.seedLiveSession(t, "revoke-all-target", "jti-revoke-all")

	if err := h.engine.RevokeAll(ctx, h.scope, "incident-all"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	// THE LOAD-BEARING ASSERTION: after the deployment-wide emergency revoke ran, the
	// recorded jti must be revoked. RED without the forceKillRow Egress fix.
	if !h.revoker.IsRevoked(jti) {
		t.Fatal("after the emergency revoke ran, the recorded jti must be revoked (RevokeAll, NFR-SEC-01)")
	}

	// Audit-first ordering preserved: exactly one revoke_all record carrying the
	// operator identity as the actor, with an empty Key (a global revoke targets
	// every session, not one).
	recs := h.audit.Records()
	if len(recs) != 1 || recs[0].Action != audit.ActionRevokeAll {
		t.Fatalf("audit records = %+v, want exactly one revoke_all", recs)
	}
	if recs[0].Caller != ksOperator.Caller || recs[0].Tenant != ksOperator.Tenant {
		t.Fatalf("revoke_all actor = {%q,%q}, want the operator {%q,%q}",
			recs[0].Tenant, recs[0].Caller, ksOperator.Tenant, ksOperator.Caller)
	}
	if recs[0].Key != "" {
		t.Fatalf("revoke_all Key = %q, want empty (a global revoke targets every session)", recs[0].Key)
	}

	// Monotonic dead mark survives a wall-clock setback (NFR-SEC-48).
	h.clk.SetWallClock(ksRevokeStart.Add(-72 * time.Hour))
	if !h.revoker.IsRevoked(jti) {
		t.Fatal("a wall-clock setback must never un-revoke a dead jti")
	}
}

// TestReconcileDerivesRevokeKeyFromSessionName guards the consistent-now reconcile
// fix: the reconcile-derived EgressBinding.FilesystemID must bind on the
// host-derived session key (== labelSessionName == row.Key) — the key the
// create-path mint records the jti under — NOT the filesystem_id label. Binding on
// the label instead would silently miss the recorded jti once the Revoker persists
// across restart, the same revoke-miss class the forceKillRow fix closes. The label
// values are deliberately DISTINCT so a regression to the label is detectable.
func TestReconcileDerivesRevokeKeyFromSessionName(t *testing.T) {
	t.Parallel()
	const sessionKey = "host-derived-row-key"
	const fsLabel = "the-real-filesystem-id"

	fake := newFakeAPI()
	fake.listResult = []container.Summary{
		{
			ID: "ctr-reconcile",
			Labels: map[string]string{
				labelManaged:      managedLabelValue,
				labelSessionName:  sessionKey,
				labelFilesystemID: fsLabel,
			},
		},
	}
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sbs, rerr := p.Reconcile(context.Background())
	if rerr != nil {
		t.Fatalf("Reconcile: %v", rerr)
	}
	if len(sbs) != 1 {
		t.Fatalf("Reconcile: want 1 re-derived sandbox, got %d (%v)", len(sbs), sbs)
	}
	// The revoke handle is the session key, NOT the filesystem_id label: a
	// reconcile-driven force-kill must address the jti recorded under row.Key.
	if got := sbs[0].Egress.FilesystemID; got != sessionKey {
		t.Fatalf("reconcile-derived Egress.FilesystemID = %q, want the session key %q (the revoke-record key, not the fs label %q)",
			got, sessionKey, fsLabel)
	}
	if got := string(sbs[0].Egress.Name); got != sessionKey {
		t.Fatalf("reconcile-derived Egress.Name = %q, want the session key %q", got, sessionKey)
	}
}
