// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// errLcInjected is the generic fault the lifecycle error-path wrappers return.
var errLcInjected = errors.New("lifecycle_test: injected fault")

// teardownFaultProvider is a RuntimeProvider whose finalizer can be armed to fail
// GracefulStop and/or ForceKill, and whose Reconcile can be armed to fail, so the
// Destroy teardown error, the Reconcile orphan force-kill error, and the
// list-orphans error are all reachable. Materialize succeeds (it is not under test
// here).
type teardownFaultProvider struct {
	gracefulErr    error
	forceKillErr   error
	reconcileErr   error
	orphans        []runtime.Sandbox
	emptyRuntimeID bool // materialize returns a sandbox with no RuntimeID (the bind fallback)
	nextID         int
}

func (p *teardownFaultProvider) Materialize(_ context.Context, spec runtime.SessionSpec) (runtime.Sandbox, error) {
	p.nextID++
	id := "ctr"
	if p.emptyRuntimeID {
		id = ""
	}
	return runtime.Sandbox{Name: spec.Name, RuntimeID: id}, nil
}
func (p *teardownFaultProvider) Teardown() runtime.RuntimeTeardown { return teardownFaultFin{p: p} }
func (p *teardownFaultProvider) Reconcile(context.Context) ([]runtime.Sandbox, error) {
	if p.reconcileErr != nil {
		return nil, p.reconcileErr
	}
	out := make([]runtime.Sandbox, len(p.orphans))
	copy(out, p.orphans)
	return out, nil
}

type teardownFaultFin struct{ p *teardownFaultProvider }

func (f teardownFaultFin) GracefulStop(context.Context, runtime.Sandbox, runtime.Duration) error {
	return f.p.gracefulErr
}
func (f teardownFaultFin) ForceKill(context.Context, runtime.Sandbox) error {
	return f.p.forceKillErr
}

// errStore wraps an in-memory listerStore and arms a fault on Release or
// RefundConcurrent-relevant Charge, plus an enumeration fault for ReservedAndActiveKeys.
type errStore struct {
	*listerStore
	failRelease       bool
	failChargeNeg     bool // fail a negative-delta (refund) Charge
	failEnumerate     bool
	failCommit        bool
	enumerateRows     []state.SessionRow
	overrideEnumerate bool
}

func (s *errStore) Commit(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	if s.failCommit {
		return state.SessionRow{}, errLcInjected
	}
	return s.listerStore.Commit(ctx, key, owner)
}

func (s *errStore) Release(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	if s.failRelease {
		return state.SessionRow{}, errLcInjected
	}
	return s.listerStore.Release(ctx, key, owner)
}

func (s *errStore) Charge(ctx context.Context, key state.QuotaKey, delta, limit int64) (int64, error) {
	if s.failChargeNeg && delta < 0 {
		return 0, errLcInjected
	}
	return s.listerStore.Charge(ctx, key, delta, limit)
}

func (s *errStore) LiveSessions(ctx context.Context) ([]state.SessionRow, error) {
	if s.failEnumerate {
		return nil, errLcInjected
	}
	if s.overrideEnumerate {
		return s.enumerateRows, nil
	}
	return s.listerStore.LiveSessions(ctx)
}

// lcDeps bundles a Manager plus the fakes for the error-path tests.
type lcDeps struct {
	mgr      *lifecycle.Manager
	store    *errStore
	provider *teardownFaultProvider
	audit    *audit.RecordingFake
}

// newErrManager builds a Manager over the fault-injecting store/provider with a
// generous quota gate at the admit cell, so a create succeeds and the destroy /
// reconcile error branches can then be armed.
func newErrManager(t *testing.T) *lcDeps {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := newListerStore(state.NewInMemory(clk))
	store := &errStore{listerStore: inner}
	provider := &teardownFaultProvider{}
	sink := audit.NewRecordingFake()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: registry.NewCustodian(store),
		Provider:  provider,
		Clock:     clk,
		Quota:     quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 100, CreateRatePerCallerPerMin: 100}),
		Handoff:   handoff.NewStager(t.TempDir()),
		Audit:     sink,
		Profile:   admission.ProfileTrustedOperator,
		Tier:      runtime.TierRunc,
	})
	return &lcDeps{mgr: mgr, store: store, provider: provider, audit: sink}
}

// TestDestroyUnattestedRejected covers the Destroy empty-identity backstop.
func TestDestroyUnattestedRejected(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	empty := ingress.AuthenticatedCaller{Channel: ingress.ChannelGateway}
	if err := d.mgr.Destroy(context.Background(), empty, "x"); !errors.Is(err, lifecycle.ErrUnattested) {
		t.Fatalf("Destroy with empty identity = %v; want ErrUnattested", err)
	}
}

// TestDestroyAuditFailureDenies covers the Destroy audit-first fail-closed branch:
// a faulted sink denies the destroy and touches no substrate.
func TestDestroyAuditFailureDenies(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	if _, err := d.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d.audit.SetFault(true, errors.New("sink down"))
	if err := d.mgr.Destroy(ctx, testCaller, "sess"); !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Destroy with faulted audit = %v; want ErrAuditWriteFailed", err)
	}
}

// TestDestroyTeardownErrorPropagates covers the Destroy teardown GracefulStop error
// branch (a non-ErrNoSuchContainer failure aborts the destroy).
func TestDestroyTeardownErrorPropagates(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	if _, err := d.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d.provider.gracefulErr = errLcInjected
	if err := d.mgr.Destroy(ctx, testCaller, "sess"); !errors.Is(err, errLcInjected) {
		t.Fatalf("Destroy with a failing teardown = %v; want the injected fault", err)
	}
}

// TestDestroyTeardownNoSuchContainerIsIdempotent covers the Destroy teardown
// idempotent branch: an already-gone container (ErrNoSuchContainer) is not a
// failure, so the destroy proceeds to release.
func TestDestroyTeardownNoSuchContainerIsIdempotent(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	if _, err := d.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d.provider.gracefulErr = runtime.ErrNoSuchContainer
	if err := d.mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy with an already-gone container = %v; want nil (idempotent)", err)
	}
}

// TestDestroyReleaseErrorPropagates covers the Destroy release error branch.
func TestDestroyReleaseErrorPropagates(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	if _, err := d.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d.store.failRelease = true
	if err := d.mgr.Destroy(ctx, testCaller, "sess"); !errors.Is(err, errLcInjected) {
		t.Fatalf("Destroy with a failing release = %v; want the injected fault", err)
	}
}

// TestDestroyReleaseConcurrencyErrorPropagates covers the Destroy
// release-concurrency error branch (and ReleaseConcurrency's RefundConcurrent error
// branch): the release succeeds, but the concurrent-counter refund fails.
func TestDestroyReleaseConcurrencyErrorPropagates(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	if _, err := d.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	d.store.failChargeNeg = true // the refund is a negative-delta Charge
	if err := d.mgr.Destroy(ctx, testCaller, "sess"); !errors.Is(err, errLcInjected) {
		t.Fatalf("Destroy with a failing refund = %v; want the injected fault", err)
	}
}

// TestStatusReturnsOwnRow covers the Status success path.
func TestStatusReturnsOwnRow(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	created, err := d.mgr.Create(ctx, input("sess"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	row, err := d.mgr.Status(ctx, testCaller, "sess")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if row.Key != created.Key {
		t.Fatalf("Status row key = %q; want the created row key %q", row.Key, created.Key)
	}
	if row.State != state.StateActive {
		t.Fatalf("Status row state = %v; want ACTIVE", row.State)
	}
}

// TestStatusUnattestedRejected covers the Status empty-identity backstop.
func TestStatusUnattestedRejected(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	empty := ingress.AuthenticatedCaller{Channel: ingress.ChannelGateway}
	if _, err := d.mgr.Status(context.Background(), empty, "x"); !errors.Is(err, lifecycle.ErrUnattested) {
		t.Fatalf("Status with empty identity = %v; want ErrUnattested", err)
	}
}

// TestStatusForeignOrAbsentNotOwned covers the Status lookup error branch: a hint
// addressing no row in the caller's namespace yields ErrNotOwned.
func TestStatusForeignOrAbsentNotOwned(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	if _, err := d.mgr.Status(context.Background(), testCaller, "never-created"); !errors.Is(err, registry.ErrNotOwned) {
		t.Fatalf("Status for an absent session = %v; want ErrNotOwned", err)
	}
}

// TestReconcileListOrphansError covers the Reconcile list-orphans error branch.
func TestReconcileListOrphansError(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	d.provider.reconcileErr = errLcInjected
	if err := d.mgr.Reconcile(context.Background()); !errors.Is(err, errLcInjected) {
		t.Fatalf("Reconcile with a failing list-orphans = %v; want the injected fault", err)
	}
}

// TestReconcileOrphanForceKillError covers the Reconcile orphan force-kill error
// branch (a non-ErrNoSuchContainer failure aborts the sweep).
func TestReconcileOrphanForceKillError(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	d.provider.orphans = []runtime.Sandbox{{Name: "orphan", RuntimeID: "ctr-orphan"}}
	d.provider.forceKillErr = errLcInjected
	if err := d.mgr.Reconcile(context.Background()); !errors.Is(err, errLcInjected) {
		t.Fatalf("Reconcile with a failing orphan force-kill = %v; want the injected fault", err)
	}
}

// TestReconcileOrphanForceKillNoSuchContainerIsIdempotent covers the Reconcile
// orphan already-gone branch.
func TestReconcileOrphanForceKillNoSuchContainerIsIdempotent(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	d.provider.orphans = []runtime.Sandbox{{Name: "orphan", RuntimeID: "ctr-orphan"}}
	d.provider.forceKillErr = runtime.ErrNoSuchContainer
	if err := d.mgr.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile with an already-gone orphan = %v; want nil (idempotent)", err)
	}
}

// TestReconcileListRowsError covers the Reconcile list-rows (enumeration) error
// branch.
func TestReconcileListRowsError(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	d.store.failEnumerate = true
	if err := d.mgr.Reconcile(context.Background()); !errors.Is(err, errLcInjected) {
		t.Fatalf("Reconcile with a failing list-rows = %v; want the injected fault", err)
	}
}

// TestReconcileSkipsActiveRow covers the Reconcile "skip non-RESERVED" branch: an
// ACTIVE row is a live session and must be left alone (only RESERVED rows are
// reclaimed). A created (ACTIVE) session survives a reconcile with no orphans.
func TestReconcileSkipsActiveRow(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()
	created, err := d.mgr.Create(ctx, input("active-sess"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// The ACTIVE row is untouched (still ACTIVE, not released).
	row, err := d.store.LookupSession(ctx, created.Key)
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("ACTIVE row state after reconcile = %v; want ACTIVE (left alone)", row.State)
	}
}

// TestReconcileReleaseReclaimedError covers the Reconcile releaseReclaimed error
// branch (and releaseReclaimed's own ReleaseRow error branch): a RESERVED row is
// enumerated but its release fails.
func TestReconcileReleaseReclaimedError(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()

	// Seed a crashed-mid-create RESERVED row, then make Release fail.
	stranded := state.Identity{Tenant: "tenant-c", Caller: "caller-3"}
	key := registry.DeriveKey(stranded, "stranded")
	cust := registry.NewCustodian(d.store)
	if _, err := cust.Reserve(ctx, key, stranded); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	d.store.failRelease = true
	if err := d.mgr.Reconcile(ctx); !errors.Is(err, errLcInjected) {
		t.Fatalf("Reconcile with a failing reclaim release = %v; want the injected fault", err)
	}
}

// TestReconcileReleaseConcurrencyError covers the Reconcile release-concurrency
// error branch: the RESERVED row releases, but returning its concurrent slot fails.
func TestReconcileReleaseConcurrencyError(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	ctx := context.Background()

	stranded := state.Identity{Tenant: "tenant-d", Caller: "caller-4"}
	key := registry.DeriveKey(stranded, "stranded2")
	cust := registry.NewCustodian(d.store)
	if _, err := cust.Reserve(ctx, key, stranded); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	d.store.failChargeNeg = true // the concurrent refund is a negative-delta Charge
	if err := d.mgr.Reconcile(ctx); !errors.Is(err, errLcInjected) {
		t.Fatalf("Reconcile with a failing concurrency refund = %v; want the injected fault", err)
	}
}

// TestCreateCommitConflictUnwinds covers stageCommit's Commit-error branch: a
// commit failure fails the create closed and reverses S6..S3, leaving no live
// container.
func TestCreateCommitConflictUnwinds(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	d.store.failCommit = true
	if _, err := d.mgr.Create(context.Background(), input("commit-fails")); err == nil {
		t.Fatal("Create with a failing Commit returned nil; want a fail-closed deny")
	}
}

// TestCreateBindFallbackOnEmptyRuntimeID covers stageBind's empty-RuntimeID
// fallback: when the provider returns no runtime id, the bind falls back to the
// host-derived key as the container-name predicate, so the create still completes
// with a bound row.
func TestCreateBindFallbackOnEmptyRuntimeID(t *testing.T) {
	t.Parallel()
	d := newErrManager(t)
	d.provider.emptyRuntimeID = true
	row, err := d.mgr.Create(context.Background(), input("empty-id"))
	if err != nil {
		t.Fatalf("Create with an empty RuntimeID = %v; want success via the host-derived fallback", err)
	}
	if row.ContainerName == "" {
		t.Fatal("bind fallback produced an empty container name; want the host-derived key")
	}
	if row.ContainerName != row.Key {
		t.Fatalf("bind fallback container name = %q; want the host-derived key %q", row.ContainerName, row.Key)
	}
}

// unstageFailStager wraps a real Stager but fails Unstage, so the create unwind's
// stageStageHandoff compensator hits its error branch.
type unstageFailStager struct{ inner handoff.Stager }

func (s unstageFailStager) Stage(ctx context.Context, name runtime.SessionName, pubKey []byte, mounts []runtime.MountIntent) (handoff.Staged, error) {
	return s.inner.Stage(ctx, name, pubKey, mounts)
}
func (s unstageFailStager) Unstage(context.Context, handoff.Staged) error { return errLcInjected }

// TestUnwindCompensatorErrorsAreSwallowed covers the error branches inside the
// stageReserve (Release), stageStageHandoff (Unstage), and stageMaterialize
// (ForceKill) compensators: when a create fails at commit, the unwind replays each
// compensator and each one ERRORS, yet the unwind runs them all and the create
// still returns its original stage error (a wedged compensator never strands a
// later one). This drives the compensator error-formatting lines.
func TestUnwindCompensatorErrorsAreSwallowed(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(lifeStart)
	inner := newListerStore(state.NewInMemory(clk))
	store := &errStore{listerStore: inner, failCommit: true, failRelease: true}
	provider := &teardownFaultProvider{forceKillErr: errLcInjected}
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: registry.NewCustodian(store),
		Provider:  provider,
		Clock:     clk,
		Quota:     quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 100, CreateRatePerCallerPerMin: 100}),
		Handoff:   unstageFailStager{inner: handoff.NewStager(t.TempDir())},
		Audit:     audit.NewRecordingFake(),
		Profile:   admission.ProfileTrustedOperator,
		Tier:      runtime.TierRunc,
	})

	// Commit fails (S7), so the unwind replays S6 (ForceKill -> error), S5 (Unstage ->
	// error), and S4 (Release -> error). The create still returns the commit error.
	if _, err := mgr.Create(context.Background(), input("all-compensators-error")); err == nil {
		t.Fatal("Create with a failing commit returned nil; want the commit error despite compensator failures")
	}
}
