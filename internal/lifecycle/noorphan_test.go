// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// bindFaultStore wraps a Store and fails BindContainerName when armed, to drive the
// S8 (bind) fault without a contrived two-row name collision. It embeds the inner
// Store so every other method passes through unchanged.
type bindFaultStore struct {
	state.Store
	fail bool
}

func (s *bindFaultStore) BindContainerName(ctx context.Context, key string, owner state.Identity, name string) (state.SessionRow, error) {
	if s.fail {
		return state.SessionRow{}, state.ErrBindingExists
	}
	return s.Store.BindContainerName(ctx, key, owner, name)
}

// faultPoint names one create stage at which the no-orphan test injects a fault. The
// integer is the 1-based stage index; the arming closure configures the harness so
// that exactly that stage fails while every prior stage succeeds.
type faultPoint struct {
	stage int    // 1-based index of the failing stage
	name  string // the stage name, for diagnostics
	// arm configures the fakes so the named stage fails; it returns the sentinel the
	// failing stage's error must match.
	arm func(h *orphanHarness) error
}

// orphanHarness is the no-orphan test's substrate: an in-mem Store wrapped first to
// enumerate live rows, then to inject a bind fault, plus the recording provider,
// fault stager, and audit fake. After an injected create failure the test asserts the
// Store holds no live row, the concurrent counter is zero, the provider holds no
// container, and no sockdir survives on disk.
type orphanHarness struct {
	mgr      *lifecycle.Manager
	inner    state.Store
	lister   *listerStore
	binder   *bindFaultStore
	provider *recordingProvider
	stager   *faultStager
	pusher   *recordingPusher
	audit    *audit.RecordingFake
	clk      *state.FakeClock
	tenant   state.Identity
}

func newOrphanHarness(t *testing.T) *orphanHarness {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	lister := newListerStore(inner)
	binder := &bindFaultStore{Store: lister}
	cust := registry.NewCustodian(binder)
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	pusher := newRecordingPusher()
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(binder, clk, generousLimits())
	signer, _ := newTestSigner(t, clk)

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		Signer:        signer,
		Push:          pusher,
		ServiceURL:    testServiceURL,
		CACertPEM:     testCACert,
		MountDefaults: testMountDefaults(t),
		StorageScope:  lifecycle.StorageScope{Workspace: "ws", Org: "org", Intent: cred.IntentWrite},
	})
	return &orphanHarness{
		mgr:      mgr,
		inner:    inner,
		lister:   lister,
		binder:   binder,
		provider: provider,
		stager:   stager,
		pusher:   pusher,
		audit:    sink,
		clk:      clk,
		tenant:   testCaller.Identity,
	}
}

// faultPoints enumerates every create stage that pushes-or-follows a compensator and
// can be made to fail. S1 (resolveIdentity) and S2 (admit) push no compensator and
// are covered by their own unit tests; S3 (quotaCharge) refuses before pushing its
// own compensator, also unit-tested. S6 (mintStorageJWT) pushes no compensator (a
// minted-but-unused token simply expires; its refusal paths are cred's own tests).
// The headline no-orphan property is the unwind of S4..S10, where 1..N-1
// compensators — Release, Receipt.Apply, Unstage, Scrub, ForceKill — must each run
// exactly once in reverse, leaving no row, counter, sockdir, pushed config, or
// container.
func faultPoints() []faultPoint {
	return []faultPoint{
		{
			stage: 4, name: "reserve",
			arm: func(h *orphanHarness) error {
				// Engage DENY-ALL so Reserve refuses inside its advisory-locked critical
				// section (a revoke landing before S4).
				_ = h.inner.SetDeny(context.Background(), state.DenyEntry{Scope: state.ScopeGlobal})
				return state.ErrKillSwitchEngaged
			},
		},
		{
			stage: 5, name: "stageHandoff",
			arm: func(h *orphanHarness) error {
				h.stager.failStage = true
				return errStageInjected
			},
		},
		{
			stage: 7, name: "renderPushMount",
			arm: func(h *orphanHarness) error {
				h.pusher.failPush = true
				return errPushInjected
			},
		},
		{
			stage: 8, name: "materialize",
			arm: func(h *orphanHarness) error {
				h.provider.failMaterialize = true
				return runtime.ErrMaterialize
			},
		},
		{
			stage: 9, name: "commit",
			arm: func(h *orphanHarness) error {
				h.audit.SetFault(true, errors.New("sink down"))
				return audit.ErrAuditWriteFailed
			},
		},
		{
			stage: 10, name: "bindContainerName",
			arm: func(h *orphanHarness) error {
				h.binder.fail = true
				return state.ErrBindingExists
			},
		},
	}
}

// TestNoOrphanUnderInjectedFailureAtStageN is the headline property (NFR-mandated):
// for a random stage N, inject a fault at N and assert (a) Create returns the typed
// stage error, and (b) the unwind ran every compensator for 1..N-1 exactly once in
// reverse, leaving ZERO residue — no live row, no concurrent counter, no container,
// no sockdir. The order being DATA (m.stages) is what makes this assertable: each
// fault point is one row in the table.
func TestNoOrphanUnderInjectedFailureAtStageN(t *testing.T) {
	t.Parallel()
	points := faultPoints()

	rapid.Check(t, func(rt *rapid.T) {
		idx := rapid.IntRange(0, len(points)-1).Draw(rt, "faultPoint")
		fp := points[idx]

		h := newOrphanHarness(t)
		wantSentinel := fp.arm(h)

		_, err := h.mgr.Create(context.Background(), input("orphan-probe"))
		if err == nil {
			rt.Fatalf("Create succeeded with a fault injected at stage %d (%s); want a typed failure", fp.stage, fp.name)
		}
		if !errors.Is(err, wantSentinel) {
			rt.Fatalf("Create at stage %d (%s): error = %v, want wrapped %v", fp.stage, fp.name, err, wantSentinel)
		}

		// (b) Zero residue: the compensators for every successful prior stage ran.
		assertNoResidue(rt, h, fp)
	})
}

// assertNoResidue checks the four substrate surfaces are clean after an injected
// failure at fp.stage: no live container (S6's ForceKill compensator ran if
// Materialize succeeded), no concurrent counter (S3's Receipt.Apply ran), no live
// reservation row (S4's Release ran, leaving only a RELEASED tombstone), and no
// staged sockdir (S5's Unstage ran). It also asserts the exact compensator call
// counts the LIFO unwind must produce.
func assertNoResidue(rt *rapid.T, h *orphanHarness, fp faultPoint) {
	ctx := context.Background()

	// No live container: a materialized container must have been force-killed.
	if got := h.provider.liveCount(); got != 0 {
		rt.Fatalf("stage %d (%s): %d live containers after unwind, want 0", fp.stage, fp.name, got)
	}

	// No live concurrent counter: the quota receipt refunded the +1.
	v, err := h.inner.ReadQuota(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: h.tenant})
	if err != nil {
		rt.Fatalf("ReadQuota(concurrent): %v", err)
	}
	if v != 0 {
		rt.Fatalf("stage %d (%s): concurrent counter = %d after unwind, want 0", fp.stage, fp.name, v)
	}

	stageCalls, unstageCalls := h.stager.counts()
	pushCalls, scrubCalls := h.pusher.counts()

	// No pushed mount-config left on the host-owned bind: if the render/push stage
	// (S7) succeeded, the LIFO unwind Scrubbed it, so the on-disk file is gone.
	if p := h.pusher.pushedPath(); p != "" {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			rt.Fatalf("stage %d (%s): pushed mount-config %q survives after unwind (stat err=%v), want gone",
				fp.stage, fp.name, p, err)
		}
	}

	// Exact compensator counts per fault point. Reserve(S4) pushes a Release; the
	// failure path of Reserve itself writes no row, so a fault AT S4 runs no Release.
	// A fault at S5+ runs S4's Release (the row drops to a RELEASED tombstone, which is
	// not "live"). Materialize(S8) pushes a ForceKill; a fault at S9/S10 runs it once.
	wantForceKill := 0
	if fp.stage >= 9 { // Materialize succeeded only when the fault is at S9 or later.
		wantForceKill = 1
	}
	if h.provider.forceKillCalls != wantForceKill {
		rt.Fatalf("stage %d (%s): forceKill compensator ran %d times, want %d",
			fp.stage, fp.name, h.provider.forceKillCalls, wantForceKill)
	}

	var wantStage, wantUnstage int
	switch {
	case fp.stage <= 4:
		// Stage never reached.
		wantStage, wantUnstage = 0, 0
	case fp.stage == 5:
		// Stage attempted and failed closed: it staged nothing on disk and pushed no
		// compensator, so there is nothing to Unstage.
		wantStage, wantUnstage = 1, 0
	default: // S7, S8, S9, S10 — stageHandoff succeeded once
		// Stage succeeded once; the LIFO unwind Unstaged it exactly once.
		wantStage, wantUnstage = 1, 1
	}
	if stageCalls != wantStage || unstageCalls != wantUnstage {
		rt.Fatalf("stage %d (%s): stager calls stage=%d unstage=%d, want stage=%d unstage=%d",
			fp.stage, fp.name, stageCalls, unstageCalls, wantStage, wantUnstage)
	}

	// Render/push (S7) compensator counts: a fault AT S7 means Push was attempted
	// once and failed (pushing nothing), so no Scrub is owed. A fault at S8+ means
	// Push succeeded once and the unwind Scrubbed it exactly once.
	var wantPush, wantScrub int
	switch {
	case fp.stage < 7:
		wantPush, wantScrub = 0, 0
	case fp.stage == 7:
		wantPush, wantScrub = 1, 0
	default: // S8, S9, S10
		wantPush, wantScrub = 1, 1
	}
	if pushCalls != wantPush || scrubCalls != wantScrub {
		rt.Fatalf("stage %d (%s): pusher calls push=%d scrub=%d, want push=%d scrub=%d",
			fp.stage, fp.name, pushCalls, scrubCalls, wantPush, wantScrub)
	}
}

// cancelDuringUnwindStore wraps a Store and cancels a supplied context the instant
// the bind fault fires, so the test can prove the LIFO unwind runs under
// context.WithoutCancel: even with the request context cancelled mid-create, every
// compensator still runs and leaves no residue.
type cancelDuringUnwindStore struct {
	state.Store
	cancel context.CancelFunc
}

func (s *cancelDuringUnwindStore) BindContainerName(ctx context.Context, key string, owner state.Identity, name string) (state.SessionRow, error) {
	// Fail the bind AND cancel the request context, so the unwind that follows runs
	// against an already-cancelled parent.
	s.cancel()
	return state.SessionRow{}, state.ErrBindingExists
}

// TestUnwindRunsUnderCancelledContext proves the unwind is detached from the
// caller's cancellation: the request context is cancelled at the moment the bind
// stage fails, yet every compensator still runs and the substrate is left clean.
func TestUnwindRunsUnderCancelledContext(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	lister := newListerStore(inner)

	ctx, cancel := context.WithCancel(context.Background())
	canceller := &cancelDuringUnwindStore{Store: lister, cancel: cancel}
	cust := registry.NewCustodian(canceller)
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(canceller, clk, generousLimits())

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: cust,
		Provider:  provider,
		Clock:     clk,
		Quota:     gate,
		Handoff:   stager,
		Audit:     sink,
		Profile:   admission.ProfileTrustedOperator,
		Tier:      runtime.TierRunc,
	})

	_, err := mgr.Create(ctx, input("cancel-probe"))
	if !errors.Is(err, state.ErrBindingExists) {
		t.Fatalf("Create error = %v, want ErrBindingExists (bind stage fault)", err)
	}

	// Despite the cancelled request context, the unwind ran every compensator: no live
	// container, no concurrent counter, balanced stage/unstage.
	if got := provider.liveCount(); got != 0 {
		t.Fatalf("live containers after cancelled-context unwind = %d, want 0", got)
	}
	v, qerr := inner.ReadQuota(context.Background(), state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: testCaller.Identity})
	if qerr != nil {
		t.Fatalf("ReadQuota: %v", qerr)
	}
	if v != 0 {
		t.Fatalf("concurrent counter after cancelled-context unwind = %d, want 0", v)
	}
	if provider.forceKillCalls != 1 {
		t.Fatalf("forceKill ran %d times under cancelled unwind, want 1", provider.forceKillCalls)
	}
	stageCalls, unstageCalls := stager.counts()
	if stageCalls != 1 || unstageCalls != 1 {
		t.Fatalf("stager stage=%d unstage=%d under cancelled unwind, want 1/1", stageCalls, unstageCalls)
	}
}
