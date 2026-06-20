// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package killswitch_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ksStart anchors the FakeClock for reproducible deny-entry Since stamps.
var ksStart = time.Date(2025, time.April, 5, 6, 7, 8, 0, time.UTC)

// owner is the host-derived identity the reserved-row fixtures are written under. It
// is the quota TARGET in the override tests — deliberately DISTINCT from operatorID
// so the operator-as-actor assertion (the actor must be WHO ACTED, not the target)
// is not vacuous.
var owner = state.Identity{Tenant: "tenant-x", Caller: "caller-x"}

// operatorID is the host-attested operator identity stamped onto the engine
// harness's OperatorScope at mint. The kill-switch records it as the audit actor
// (actor.user = who acted) for every privileged action, so the actor-assertion tests
// check the emitted Record carries THIS identity, distinct from owner.
var operatorID = state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}

// recordingProvider counts ForceKill calls and tracks the live RuntimeIDs so a test
// can prove RevokeAll force-killed a reserved row. It never fails.
type recordingProvider struct {
	mu             sync.Mutex
	forceKillCalls int
	live           map[string]bool
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{live: map[string]bool{}}
}

func (p *recordingProvider) Materialize(ctx context.Context, spec runtime.SessionSpec) (runtime.Sandbox, error) {
	return runtime.Sandbox{}, runtime.ErrNotImplemented
}

func (p *recordingProvider) Teardown() runtime.RuntimeTeardown { return recordingTeardown{p: p} }

func (p *recordingProvider) Reconcile(ctx context.Context) ([]runtime.Sandbox, error) {
	return nil, nil
}

type recordingTeardown struct{ p *recordingProvider }

func (t recordingTeardown) GracefulStop(ctx context.Context, sess runtime.Sandbox, _ runtime.Duration) error {
	return nil
}

func (t recordingTeardown) ForceKill(ctx context.Context, sess runtime.Sandbox) error {
	t.p.mu.Lock()
	defer t.p.mu.Unlock()
	t.p.forceKillCalls++
	delete(t.p.live, sess.RuntimeID)
	return nil
}

// listerStore wraps an in-memory Store with the LiveLister capability so the engine
// can enumerate the RESERVED+ACTIVE rows for force-kill-every. It records every
// reserved key.
type listerStore struct {
	state.Store
	mu   sync.Mutex
	keys map[string]bool
}

func newListerStore(inner state.Store) *listerStore {
	return &listerStore{Store: inner, keys: map[string]bool{}}
}

func (s *listerStore) Reserve(ctx context.Context, key string, ownerID state.Identity) (state.SessionRow, error) {
	row, err := s.Store.Reserve(ctx, key, ownerID)
	if err == nil {
		s.mu.Lock()
		s.keys[key] = true
		s.mu.Unlock()
	}
	return row, err
}

func (s *listerStore) LiveSessions(ctx context.Context) ([]state.SessionRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	keys := make([]string, 0, len(s.keys))
	for k := range s.keys {
		keys = append(keys, k)
	}
	s.mu.Unlock()
	var out []state.SessionRow
	for _, k := range keys {
		row, err := s.Store.LookupSession(ctx, k)
		if err != nil {
			if errors.Is(err, state.ErrReservationNotFound) {
				continue
			}
			return nil, err
		}
		if row.State == state.StateReserved || row.State == state.StateActive {
			out = append(out, row)
		}
	}
	return out, nil
}

// engineHarness bundles an Engine over fakes plus the genuine operator scope.
type engineHarness struct {
	engine   *killswitch.Engine
	store    *listerStore
	cust     *registry.Custodian
	provider *recordingProvider
	audit    *audit.RecordingFake
	scope    ingress.OperatorScope
}

func newEngineHarness() *engineHarness {
	clk := state.NewFakeClock(ksStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	cust := registry.NewCustodian(store)
	provider := newRecordingProvider()
	sink := audit.NewRecordingFake()
	engine := killswitch.NewEngine(store, cust, provider, clk, sink)
	scope := ingress.NewOperatorSeam().Mint(operatorID)
	return &engineHarness{
		engine:   engine,
		store:    store,
		cust:     cust,
		provider: provider,
		audit:    sink,
		scope:    scope,
	}
}

// reserveRow seeds a RESERVED row under owner via the Custodian, the same path a
// just-reserved-not-yet-committed create takes.
func (h *engineHarness) reserveRow(t *testing.T, handle string) registry.Key {
	t.Helper()
	key := registry.DeriveKey(owner, handle)
	if _, err := h.cust.Reserve(context.Background(), key, owner); err != nil {
		t.Fatalf("seed reserve %q: %v", handle, err)
	}
	h.provider.mu.Lock()
	h.provider.live[key.String()] = true
	h.provider.mu.Unlock()
	return key
}

// TestRevokeAllForceKillsJustReservedRow proves the must-fix: RevokeAll force-kills a
// RESERVED row (not only ACTIVE), engages DENY-ALL, and audits first.
func TestRevokeAllForceKillsJustReservedRow(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()

	key := h.reserveRow(t, "just-reserved")

	if err := h.engine.RevokeAll(ctx, h.scope, "incident-42"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	// The reserved row was force-killed.
	if h.provider.forceKillCalls != 1 {
		t.Fatalf("RevokeAll force-killed %d rows, want 1 (the reserved row)", h.provider.forceKillCalls)
	}
	// DENY-ALL is engaged: a fresh Reserve is refused with the kill-switch sentinel.
	other := registry.DeriveKey(owner, "after-deny-all")
	if _, err := h.cust.Reserve(ctx, other, owner); !errors.Is(err, state.ErrKillSwitchEngaged) {
		t.Fatalf("post-RevokeAll Reserve error = %v, want ErrKillSwitchEngaged", err)
	}
	// The row was released to the tombstone.
	row, err := h.store.LookupSession(ctx, key.String())
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}
	if row.State != state.StateReleased {
		t.Fatalf("force-killed row state = %v, want RELEASED", row.State)
	}
	// Exactly one revoke_all audit record, emitted first, carrying the OPERATOR
	// identity as the actor (actor.user = who acted), never the row owner.
	recs := h.audit.Records()
	if len(recs) != 1 || recs[0].Action != audit.ActionRevokeAll {
		t.Fatalf("audit records = %+v, want one revoke_all", recs)
	}
	if recs[0].Caller != operatorID.Caller || recs[0].Tenant != operatorID.Tenant {
		t.Fatalf("revoke_all actor = {%q,%q}, want the operator {%q,%q}",
			recs[0].Tenant, recs[0].Caller, operatorID.Tenant, operatorID.Caller)
	}
}

// TestRevokeOneAuthorsSessionDenyAndForceKills proves RevokeOne denylists exactly the
// targeted session and force-kills its live row.
func TestRevokeOneAuthorsSessionDenyAndForceKills(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()

	key := h.reserveRow(t, "target")
	// A second, untargeted session must survive RevokeOne.
	otherKey := h.reserveRow(t, "bystander")

	if err := h.engine.RevokeOne(ctx, h.scope, key.String(), "abuse"); err != nil {
		t.Fatalf("RevokeOne: %v", err)
	}

	if h.provider.forceKillCalls != 1 {
		t.Fatalf("RevokeOne force-killed %d rows, want 1 (the target)", h.provider.forceKillCalls)
	}
	// The targeted key is denylisted: a re-reserve of it is refused.
	if _, err := h.cust.Reserve(ctx, key, owner); !errors.Is(err, state.ErrSessionDenied) {
		t.Fatalf("re-reserve of revoked key error = %v, want ErrSessionDenied", err)
	}
	// The bystander key is NOT denylisted (it is still RESERVED, so a re-reserve hits
	// ErrReservationExists, not ErrSessionDenied — proving it was not globally denied).
	if _, err := h.cust.Reserve(ctx, otherKey, owner); !errors.Is(err, state.ErrReservationExists) {
		t.Fatalf("bystander re-reserve error = %v, want ErrReservationExists (not denied)", err)
	}
	recs := h.audit.Records()
	if len(recs) != 1 || recs[0].Action != audit.ActionRevokeOne || recs[0].Key != key.String() {
		t.Fatalf("audit records = %+v, want one revoke_one for the target key", recs)
	}
	// The actor is the OPERATOR who issued the revoke, never the targeted row owner.
	if recs[0].Caller != operatorID.Caller || recs[0].Tenant != operatorID.Tenant {
		t.Fatalf("revoke_one actor = {%q,%q}, want the operator {%q,%q}",
			recs[0].Tenant, recs[0].Caller, operatorID.Tenant, operatorID.Caller)
	}
}

// TestRevokeAuditFailureDeniesAndAuthorsNothing proves the audit-first fail-closed
// branch: with the sink faulted, RevokeAll denies the revoke, engages no DENY-ALL,
// and force-kills nothing.
func TestRevokeAuditFailureDeniesAndAuthorsNothing(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()

	key := h.reserveRow(t, "survivor")
	h.audit.SetFault(true, errors.New("sink down"))

	err := h.engine.RevokeAll(ctx, h.scope, "incident")
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("RevokeAll with faulted audit error = %v, want ErrAuditWriteFailed", err)
	}

	// No DENY-ALL engaged: a fresh Reserve still succeeds.
	if h.provider.forceKillCalls != 0 {
		t.Fatalf("force-killed %d rows after a denied revoke, want 0", h.provider.forceKillCalls)
	}
	other := registry.DeriveKey(owner, "still-allowed")
	if _, err := h.cust.Reserve(ctx, other, owner); err != nil {
		t.Fatalf("Reserve after denied revoke = %v, want success (no DENY-ALL)", err)
	}
	// The targeted session was never released.
	row, lerr := h.store.LookupSession(ctx, key.String())
	if lerr != nil {
		t.Fatalf("LookupSession: %v", lerr)
	}
	if row.State != state.StateReserved {
		t.Fatalf("survivor row state = %v, want RESERVED (revoke denied)", row.State)
	}
}

// TestRevokeRejectsInvalidScope proves the runtime backstop to the compile-time
// seal: a zero-value (forged) OperatorScope is refused before any audit or Store
// write.
func TestRevokeRejectsInvalidScope(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()

	var forged ingress.OperatorScope // zero value: Valid() is false
	if err := h.engine.RevokeAll(ctx, forged, "x"); !errors.Is(err, killswitch.ErrScopeInvalid) {
		t.Fatalf("RevokeAll with forged scope = %v, want ErrScopeInvalid", err)
	}
	if err := h.engine.RevokeOne(ctx, forged, "k", "x"); !errors.Is(err, killswitch.ErrScopeInvalid) {
		t.Fatalf("RevokeOne with forged scope = %v, want ErrScopeInvalid", err)
	}
	// Nothing authored, nothing audited.
	if h.audit.Len() != 0 {
		t.Fatalf("audit recorded %d events for a forged-scope revoke, want 0", h.audit.Len())
	}
}

// ed25519SOAR is a concrete SOARVerifier over an Ed25519 SOAR principal key, the
// shape the operator adapter supplies in a later step. On a successful verify it
// surfaces the SOAR PRINCIPAL identity — the authority for a SOAR-driven revoke and
// thus the audit actor (P2-R2). The accept/reject test exercises it here so the
// verify-then-mint contract has a real implementation.
type ed25519SOAR struct {
	pub       ed25519.PublicKey
	principal state.Identity
}

func (v ed25519SOAR) Verify(_ context.Context, payload, sig []byte) (state.Identity, error) {
	if !ed25519.Verify(v.pub, payload, sig) {
		return state.Identity{}, fmt.Errorf("%w: signature did not verify", killswitch.ErrSOARUnverified)
	}
	return v.principal, nil
}

// compile-time proof the concrete verifier satisfies the port.
var _ killswitch.SOARVerifier = ed25519SOAR{}

// TestSOARVerifierAcceptReject proves the verify-then-mint gate: a valid SOAR
// signature verifies and surfaces the principal identity, a tampered one rejects
// with ErrSOARUnverified — so an unverifiable SOAR call never reaches the Engine.
func TestSOARVerifierAcceptReject(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	principal := state.Identity{Tenant: "soar-tenant", Caller: "soar-principal"}
	v := ed25519SOAR{pub: pub, principal: principal}
	payload := []byte(`{"action":"revoke_all","reason":"incident"}`)
	sig := ed25519.Sign(priv, payload)

	gotID, err := v.Verify(context.Background(), payload, sig)
	if err != nil {
		t.Fatalf("Verify of a valid signature = %v, want nil (accept)", err)
	}
	if gotID != principal {
		t.Fatalf("Verify surfaced principal %+v, want %+v", gotID, principal)
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF
	if _, err := v.Verify(context.Background(), payload, tampered); !errors.Is(err, killswitch.ErrSOARUnverified) {
		t.Fatalf("Verify of a tampered signature = %v, want ErrSOARUnverified (reject)", err)
	}
}

// TestLiftDenyClearsSessionDeny proves the operator denylist-edit: it audits first,
// then lifts a previously authored per-session deny so the session admits again. It
// does not touch the global posture.
func TestLiftDenyClearsSessionDeny(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()
	key := registry.DeriveKey(owner, "denied-then-lifted")

	// Author a per-session deny, then lift it.
	if err := h.engine.RevokeOne(ctx, h.scope, key.String(), "incident"); err != nil {
		t.Fatalf("RevokeOne: %v", err)
	}
	if err := h.engine.LiftDeny(ctx, h.scope, key.String(), "false-positive"); err != nil {
		t.Fatalf("LiftDeny: %v", err)
	}

	// The per-session deny is gone: a fresh Reserve under the lifted key succeeds.
	if _, err := h.cust.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("Reserve after LiftDeny = %v, want success (deny lifted)", err)
	}
	// The edit was audited, with the OPERATOR identity as the actor.
	rec, ok := recordFor(h.audit, audit.ActionEditDenylist)
	if !ok {
		t.Fatal("LiftDeny did not emit an ActionEditDenylist record")
	}
	if rec.Caller != operatorID.Caller || rec.Tenant != operatorID.Tenant {
		t.Fatalf("lift-deny actor = {%q,%q}, want the operator {%q,%q}",
			rec.Tenant, rec.Caller, operatorID.Tenant, operatorID.Caller)
	}
}

// TestLiftDenyAuditFailureDenies proves LiftDeny is audit-first fail-closed: a
// faulted sink denies the edit and the per-session deny is NOT lifted.
func TestLiftDenyAuditFailureDenies(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()
	key := registry.DeriveKey(owner, "stays-denied")

	if err := h.engine.RevokeOne(ctx, h.scope, key.String(), "incident"); err != nil {
		t.Fatalf("RevokeOne: %v", err)
	}
	h.audit.SetFault(true, errors.New("sink down"))

	if err := h.engine.LiftDeny(ctx, h.scope, key.String(), "x"); !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("LiftDeny with faulted audit = %v, want ErrAuditWriteFailed", err)
	}
	// The deny was NOT lifted: a Reserve under the still-denied key is refused.
	if _, err := h.cust.Reserve(ctx, key, owner); !errors.Is(err, state.ErrSessionDenied) && !errors.Is(err, state.ErrKillSwitchEngaged) {
		t.Fatalf("Reserve after a denied LiftDeny = %v, want a deny refusal (edit not applied)", err)
	}
}

// TestLiftDenyRejectsInvalidScope and global key. A forged scope is refused before
// any audit; an empty key (the global posture) is refused by this per-session path.
func TestLiftDenyRejectsInvalidScopeAndGlobalKey(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()

	var forged ingress.OperatorScope
	if err := h.engine.LiftDeny(ctx, forged, "k", "x"); !errors.Is(err, killswitch.ErrScopeInvalid) {
		t.Fatalf("LiftDeny with forged scope = %v, want ErrScopeInvalid", err)
	}
	if err := h.engine.LiftDeny(ctx, h.scope, "", "x"); err == nil {
		t.Fatal("LiftDeny with an empty key returned nil; want a refusal (global posture not lifted here)")
	}
}

// TestOverrideQuotaChargesAndAudits proves the operator quota-override: it audits
// first, then applies the operator-authored delta through the atomic Charge.
func TestOverrideQuotaChargesAndAudits(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()
	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}

	// Grant +5 headroom (limit 10).
	if err := h.engine.OverrideQuota(ctx, h.scope, key, 5, 10, "burst grant"); err != nil {
		t.Fatalf("OverrideQuota: %v", err)
	}
	got, err := h.store.ReadQuota(ctx, key)
	if err != nil {
		t.Fatalf("ReadQuota: %v", err)
	}
	if got != 5 {
		t.Fatalf("counter after OverrideQuota(+5) = %d, want 5", got)
	}
	// The audit actor is the OPERATOR who issued the override (scope.Identity), NOT the
	// quota TARGET (key.Identity == owner). The target is the OBJECT of the action; the
	// operator is its subject. This is the load-bearing OverrideQuota ruling: actor.user
	// is WHO ACTED, so an override of owner's counter records the operator, not owner.
	rec, ok := recordFor(h.audit, audit.ActionOverrideQuota)
	if !ok {
		t.Fatal("OverrideQuota did not emit an ActionOverrideQuota record")
	}
	if rec.Caller != operatorID.Caller || rec.Tenant != operatorID.Tenant {
		t.Fatalf("override-quota actor = {%q,%q}, want the operator {%q,%q}",
			rec.Tenant, rec.Caller, operatorID.Tenant, operatorID.Caller)
	}
	if rec.Caller == owner.Caller && rec.Tenant == owner.Tenant {
		t.Fatalf("override-quota actor = the quota TARGET %+v; the actor must be the operator, not the target", owner)
	}
}

// TestOverrideQuotaAuditFailureDenies proves OverrideQuota is audit-first
// fail-closed: a faulted sink denies the override and no counter moves.
func TestOverrideQuotaAuditFailureDenies(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()
	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}

	h.audit.SetFault(true, errors.New("sink down"))
	if err := h.engine.OverrideQuota(ctx, h.scope, key, 5, 10, "x"); !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("OverrideQuota with faulted audit = %v, want ErrAuditWriteFailed", err)
	}
	got, err := h.store.ReadQuota(ctx, key)
	if err != nil {
		t.Fatalf("ReadQuota: %v", err)
	}
	if got != 0 {
		t.Fatalf("counter after a denied OverrideQuota = %d, want 0 (no counter moved)", got)
	}
}

// recordFor returns the first recorded Record for action and whether one was found,
// so an actor-assertion test can inspect the emitted actor.user fields.
func recordFor(sink *audit.RecordingFake, action audit.Action) (audit.Record, bool) {
	for _, rec := range sink.Records() {
		if rec.Action == action {
			return rec, true
		}
	}
	return audit.Record{}, false
}
