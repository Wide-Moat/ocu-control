// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package killswitch_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// errInjected is the generic fault the wrappers below return when armed.
var errInjected = errors.New("killswitch_test: injected store fault")

// faultStore wraps an in-memory Store (kept enumerable by listerStore) and arms a
// fault on a single mutator at a time, so each Engine error branch (SetDeny,
// LookupSession, ClearDeny, Charge) is driven without a real store outage. It is
// the killswitch analogue of the audit RecordingFake's SetFault.
type faultStore struct {
	state.Store
	mu            sync.Mutex
	failSetDeny   bool
	failLookup    bool
	failClearDeny bool
	failCharge    bool
	failRelease   bool
}

func (s *faultStore) Release(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	s.mu.Lock()
	fail := s.failRelease
	s.mu.Unlock()
	if fail {
		return state.SessionRow{}, errInjected
	}
	return s.Store.Release(ctx, key, owner)
}

func (s *faultStore) SetDeny(ctx context.Context, entry state.DenyEntry) error {
	s.mu.Lock()
	fail := s.failSetDeny
	s.mu.Unlock()
	if fail {
		return errInjected
	}
	return s.Store.SetDeny(ctx, entry)
}

func (s *faultStore) LookupSession(ctx context.Context, key string) (state.SessionRow, error) {
	s.mu.Lock()
	fail := s.failLookup
	s.mu.Unlock()
	if fail {
		return state.SessionRow{}, errInjected
	}
	return s.Store.LookupSession(ctx, key)
}

func (s *faultStore) ClearDeny(ctx context.Context, scope state.DenyScope, key string) error {
	s.mu.Lock()
	fail := s.failClearDeny
	s.mu.Unlock()
	if fail {
		return errInjected
	}
	return s.Store.ClearDeny(ctx, scope, key)
}

func (s *faultStore) Charge(ctx context.Context, key state.QuotaKey, delta, limit int64) (int64, error) {
	s.mu.Lock()
	fail := s.failCharge
	s.mu.Unlock()
	if fail {
		return 0, errInjected
	}
	return s.Store.Charge(ctx, key, delta, limit)
}

// LiveSessions forwards to the wrapped listerStore so the registry's LiveLister
// type assertion sees the enumeration capability through this wrapper. Without it
// faultStore would shadow the embedded interface and ReservedAndActiveKeys would
// fail closed with ErrEnumerationUnsupported.
func (s *faultStore) LiveSessions(ctx context.Context) ([]state.SessionRow, error) {
	type liveLister interface {
		LiveSessions(context.Context) ([]state.SessionRow, error)
	}
	if ll, ok := s.Store.(liveLister); ok {
		return ll.LiveSessions(ctx)
	}
	return nil, registry.ErrEnumerationUnsupported
}

// faultProvider's finalizer can be armed to fail ForceKill, exercising the
// forceKillRow non-ErrNoSuchContainer branch.
type faultProvider struct {
	mu            sync.Mutex
	forceKillErr  error
	forceKillCall int
}

func (p *faultProvider) Materialize(context.Context, runtime.SessionSpec) (runtime.Sandbox, error) {
	return runtime.Sandbox{}, runtime.ErrNotImplemented
}
func (p *faultProvider) Teardown() runtime.RuntimeTeardown                    { return faultTeardown{p: p} }
func (p *faultProvider) Reconcile(context.Context) ([]runtime.Sandbox, error) { return nil, nil }

type faultTeardown struct{ p *faultProvider }

func (t faultTeardown) GracefulStop(context.Context, runtime.Sandbox, runtime.Duration) error {
	return nil
}
func (t faultTeardown) ForceKill(context.Context, runtime.Sandbox) error {
	t.p.mu.Lock()
	defer t.p.mu.Unlock()
	t.p.forceKillCall++
	return t.p.forceKillErr
}

// newFaultEngine builds an Engine over the fault-injecting store and provider plus
// a genuine operator scope. It returns the engine, the fault store (to arm faults),
// the audit sink, and the scope.
func newFaultEngine(t *testing.T) (*killswitch.Engine, *faultStore, *audit.RecordingFake, ingress.OperatorScope) {
	t.Helper()
	clk := state.NewFakeClock(ksStart)
	inner := newListerStore(state.NewInMemory(clk))
	fs := &faultStore{Store: inner}
	cust := registry.NewCustodian(fs)
	sink := audit.NewRecordingFake()
	eng := killswitch.NewEngine(fs, cust, &faultProvider{}, clk, sink)
	scope := ingress.NewOperatorSeam().Mint(operatorID)
	return eng, fs, sink, scope
}

// TestRevokeOneAuditFailureDenies covers the RevokeOne audit-first fail-closed
// branch (the RevokeAll/LiftDeny/Override analogues are already tested).
func TestRevokeOneAuditFailureDenies(t *testing.T) {
	t.Parallel()
	eng, _, sink, scope := newFaultEngine(t)
	sink.SetFault(true, errors.New("sink down"))

	err := eng.RevokeOne(context.Background(), scope, "some-key", "incident")
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("RevokeOne with faulted audit = %v; want ErrAuditWriteFailed", err)
	}
}

// TestRevokeOneSetDenyFailure covers the RevokeOne SetDeny error branch: the audit
// succeeds, then the durable deny write fails and the error propagates.
func TestRevokeOneSetDenyFailure(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	fs.mu.Lock()
	fs.failSetDeny = true
	fs.mu.Unlock()

	err := eng.RevokeOne(context.Background(), scope, "some-key", "incident")
	if !errors.Is(err, errInjected) {
		t.Fatalf("RevokeOne with failing SetDeny = %v; want the injected store fault", err)
	}
}

// TestRevokeOneLookupFailure covers the forceKillKey lookup error branch (a
// non-not-found lookup error during the post-deny reclaim).
func TestRevokeOneLookupFailure(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	fs.mu.Lock()
	fs.failLookup = true
	fs.mu.Unlock()

	err := eng.RevokeOne(context.Background(), scope, "some-key", "incident")
	if !errors.Is(err, errInjected) {
		t.Fatalf("RevokeOne with failing LookupSession = %v; want the injected store fault", err)
	}
}

// TestRevokeOneForceKillKeyAlreadyReleased covers the forceKillKey already-released
// branch: a key whose row is in the RELEASED tombstone has nothing live to kill, so
// RevokeOne authors the deny and returns nil without a force-kill.
func TestRevokeOneForceKillKeyAlreadyReleased(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	ctx := context.Background()

	// Reserve then release a row so it sits in the RELEASED tombstone.
	cust := registry.NewCustodian(fs)
	key := registry.DeriveKey(owner, "released-key")
	if _, err := cust.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	if _, err := cust.Release(ctx, key, owner); err != nil {
		t.Fatalf("seed release: %v", err)
	}

	if err := eng.RevokeOne(ctx, scope, key.String(), "incident"); err != nil {
		t.Fatalf("RevokeOne over an already-released row = %v; want nil", err)
	}
	// The session deny was still authored.
	deny, _ := fs.LoadDeny(ctx)
	found := false
	for _, d := range deny {
		if d.Scope == state.ScopeSession && d.Key == key.String() {
			found = true
		}
	}
	if !found {
		t.Fatalf("RevokeOne over a released row did not author the session deny; entries=%v", deny)
	}
}

// TestRevokeAllSetDenyFailure covers the RevokeAll SetDeny error branch.
func TestRevokeAllSetDenyFailure(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	fs.mu.Lock()
	fs.failSetDeny = true
	fs.mu.Unlock()

	err := eng.RevokeAll(context.Background(), scope, "incident")
	if !errors.Is(err, errInjected) {
		t.Fatalf("RevokeAll with failing SetDeny = %v; want the injected store fault", err)
	}
}

// TestRevokeAllForceKillRowError covers the RevokeAll force-kill-row error branch:
// DENY-ALL engages, the enumeration succeeds, but a force-kill on a live row fails
// and RevokeAll returns the first such error (having continued the sweep).
func TestRevokeAllForceKillRowError(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(ksStart)
	inner := newListerStore(state.NewInMemory(clk))
	fs := &faultStore{Store: inner}
	cust := registry.NewCustodian(fs)
	sink := audit.NewRecordingFake()
	provider := &faultProvider{forceKillErr: errInjected}
	eng := killswitch.NewEngine(fs, cust, provider, clk, sink)
	scope := ingress.NewOperatorSeam().Mint(operatorID)
	ctx := context.Background()

	// Seed a live RESERVED row so the sweep has something to force-kill.
	key := registry.DeriveKey(owner, "live-row")
	if _, err := cust.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}

	err := eng.RevokeAll(ctx, scope, "incident")
	if !errors.Is(err, errInjected) {
		t.Fatalf("RevokeAll with a failing force-kill = %v; want the injected force-kill fault", err)
	}
	// DENY-ALL still engaged despite the force-kill error (the deny is authoritative).
	if _, rerr := cust.Reserve(ctx, registry.DeriveKey(owner, "after"), owner); !errors.Is(rerr, state.ErrKillSwitchEngaged) {
		t.Fatalf("post-RevokeAll Reserve = %v; want ErrKillSwitchEngaged (deny authored despite kill error)", rerr)
	}
}

// TestRevokeOneForceReleaseRowError covers the forceKillRow ForceReleaseRow error
// branch: the ForceKill succeeds, but driving the row to the RELEASED tombstone
// fails and the error propagates. We seed a live RESERVED row, arm the release
// fault, and revoke it.
func TestRevokeOneForceReleaseRowError(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	ctx := context.Background()

	cust := registry.NewCustodian(fs)
	key := registry.DeriveKey(owner, "release-fails")
	if _, err := cust.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	fs.mu.Lock()
	fs.failRelease = true
	fs.mu.Unlock()

	err := eng.RevokeOne(ctx, scope, key.String(), "incident")
	if !errors.Is(err, errInjected) {
		t.Fatalf("RevokeOne with a failing force-release = %v; want the injected release fault", err)
	}
}

// nonEnumerableStore wraps a state.Store but does NOT promote LiveSessions: it
// embeds the state.Store INTERFACE, whose method set carries no LiveSessions, so
// the concrete *nonEnumerableStore does not satisfy registry.LiveLister even though
// the underlying in-memory value now does. It models a hypothetical Store leg that
// has not opted into live enumeration, keeping the RevokeAll fail-closed branch
// under test after both shipped legs grew the capability.
type nonEnumerableStore struct {
	state.Store
}

// TestRevokeAllEnumerationUnsupported covers the RevokeAll enumerate error branch: a
// Store with no live-row enumeration surfaces ErrEnumerationUnsupported rather than
// silently treating an empty list as "no live rows". Both SHIPPED legs (in-memory,
// Postgres) now implement LiveSessions — proven by the store conformance suite — so
// this case wraps the in-memory store in a non-promoting shim to keep the
// fail-closed branch exercised.
func TestRevokeAllEnumerationUnsupported(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(ksStart)
	bare := &nonEnumerableStore{Store: state.NewInMemory(clk)}
	cust := registry.NewCustodian(bare)
	sink := audit.NewRecordingFake()
	eng := killswitch.NewEngine(bare, cust, &faultProvider{}, clk, sink)
	scope := ingress.NewOperatorSeam().Mint(operatorID)

	err := eng.RevokeAll(context.Background(), scope, "incident")
	if !errors.Is(err, registry.ErrEnumerationUnsupported) {
		t.Fatalf("RevokeAll on a non-enumerable Store = %v; want ErrEnumerationUnsupported", err)
	}
}

// TestLiftDenyClearFailure covers the LiftDeny ClearDeny error branch: the audit
// succeeds, then the clear fails and the error propagates.
func TestLiftDenyClearFailure(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	fs.mu.Lock()
	fs.failClearDeny = true
	fs.mu.Unlock()

	err := eng.LiftDeny(context.Background(), scope, "some-key", "false-positive")
	if !errors.Is(err, errInjected) {
		t.Fatalf("LiftDeny with failing ClearDeny = %v; want the injected store fault", err)
	}
}

// TestResumeAllAuditFailureDeniesAndKeepsDeny covers the ResumeAll audit-first
// fail-closed branch: with the sink faulted, ResumeAll returns ErrAuditWriteFailed
// and does NOT clear the global deny — a still-seeded ScopeGlobal entry survives, so
// the durable posture and the trail never disagree.
func TestResumeAllAuditFailureDeniesAndKeepsDeny(t *testing.T) {
	t.Parallel()
	eng, fs, sink, scope := newFaultEngine(t)
	ctx := context.Background()

	// Seed an operator-authored global deny that the faulted resume must NOT clear.
	if err := fs.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal, Reason: "engaged"}); err != nil {
		t.Fatalf("seed global deny: %v", err)
	}
	sink.SetFault(true, errors.New("sink down"))

	if err := eng.ResumeAll(ctx, scope, "all-clear"); !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("ResumeAll with faulted audit = %v; want ErrAuditWriteFailed", err)
	}

	// The global deny survives the denied resume.
	deny, err := fs.LoadDeny(ctx)
	if err != nil {
		t.Fatalf("LoadDeny: %v", err)
	}
	found := false
	for _, d := range deny {
		if d.Scope == state.ScopeGlobal {
			found = true
		}
	}
	if !found {
		t.Fatalf("ResumeAll with a faulted audit cleared the global deny; it must survive a denied resume. entries=%v", deny)
	}
}

// TestResumeAllClearFailure covers the ResumeAll ClearDeny error branch: the audit
// succeeds, then the durable clear fails and the injected store fault propagates.
func TestResumeAllClearFailure(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	fs.mu.Lock()
	fs.failClearDeny = true
	fs.mu.Unlock()

	err := eng.ResumeAll(context.Background(), scope, "all-clear")
	if !errors.Is(err, errInjected) {
		t.Fatalf("ResumeAll with failing ClearDeny = %v; want the injected store fault", err)
	}
}

// TestResumeAllInvalidScope covers the ResumeAll scope-invalid backstop to the
// compile-time seal: a forged zero-value scope is refused before any audit or clear.
func TestResumeAllInvalidScope(t *testing.T) {
	t.Parallel()
	eng, _, sink, _ := newFaultEngine(t)
	var forged ingress.OperatorScope // zero value: Valid() is false

	if err := eng.ResumeAll(context.Background(), forged, "x"); !errors.Is(err, killswitch.ErrScopeInvalid) {
		t.Fatalf("ResumeAll with a forged scope = %v; want ErrScopeInvalid", err)
	}
	if sink.Len() != 0 {
		t.Fatalf("ResumeAll with a forged scope audited %d records; want 0", sink.Len())
	}
}

// TestOverrideQuotaInvalidScope covers the OverrideQuota scope-invalid backstop.
func TestOverrideQuotaInvalidScope(t *testing.T) {
	t.Parallel()
	eng, _, sink, _ := newFaultEngine(t)
	var forged ingress.OperatorScope // zero value: Valid() is false

	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
	if err := eng.OverrideQuota(context.Background(), forged, key, 1, 10, "x"); !errors.Is(err, killswitch.ErrScopeInvalid) {
		t.Fatalf("OverrideQuota with a forged scope = %v; want ErrScopeInvalid", err)
	}
	if sink.Len() != 0 {
		t.Fatalf("OverrideQuota with a forged scope audited %d records; want 0", sink.Len())
	}
}

// TestOverrideQuotaChargeFailure covers the OverrideQuota Charge error branch: the
// audit succeeds, then the atomic Charge fails (e.g. ErrQuotaExceeded) and the typed
// refusal propagates.
func TestOverrideQuotaChargeFailure(t *testing.T) {
	t.Parallel()
	eng, fs, _, scope := newFaultEngine(t)
	fs.mu.Lock()
	fs.failCharge = true
	fs.mu.Unlock()

	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
	err := eng.OverrideQuota(context.Background(), scope, key, 5, 10, "burst")
	if !errors.Is(err, errInjected) {
		t.Fatalf("OverrideQuota with failing Charge = %v; want the injected store fault", err)
	}
}
