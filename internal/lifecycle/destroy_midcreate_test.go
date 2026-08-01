// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// commitHookStore wraps the harness store and runs afterCommit exactly once,
// synchronously, immediately after a successful Commit -- that is, INSIDE the
// create pipeline, in the commit->bind window. It turns the probabilistic
// TestRace_CreateVsDestroySameKey interleaving (~1 orphan in hundreds of rounds)
// into a deterministic schedule: the destroy is guaranteed to observe the row
// ACTIVE with no container name bound yet.
type commitHookStore struct {
	*listerStore
	once        sync.Once
	afterCommit func()
}

func (s *commitHookStore) Commit(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	row, err := s.listerStore.Commit(ctx, key, owner)
	if err == nil && s.afterCommit != nil {
		s.once.Do(s.afterCommit)
	}
	return row, err
}

// TestDestroyInCommitBindWindowLeavesNoOrphan pins the root cause of the
// TestRace_CreateVsDestroySameKey orphan (#89), deterministically: a Destroy
// that lands between the create's commit (row ACTIVE) and its bind (container
// name recorded) snapshots the row with ContainerName still empty, so its
// teardown cannot address the container; it then Releases the row to the
// tombstone. The create's bind stage MUST then refuse (the row is terminally
// RELEASED) so the create unwinds and its materialize compensator removes the
// container it created.
//
// Before the tombstone guard, BindContainerName silently succeeded onto the
// RELEASED row: the create reported SUCCESS for a session the destroy had
// already torn down, no unwind ran, and the container leaked -- exactly the
// activeRows==0 && liveCount==1 orphan the race test catches probabilistically.
func TestDestroyInCommitBindWindowLeavesNoOrphan(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const hint = "destroyed-mid-create"

	clk := state.NewFakeClock(lifeStart)
	hook := &commitHookStore{listerStore: newListerStore(state.NewInMemory(clk))}
	cust := registry.NewCustodian(hook)
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(hook, clk, generousLimits())

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
	})

	// The destroy runs synchronously inside the create's commit->bind window.
	var destroyErr error
	hook.afterCommit = func() { destroyErr = mgr.Destroy(ctx, testCaller, hint) }

	_, createErr := mgr.Create(ctx, input(hint))

	// The destroy legitimately tore down the just-committed ACTIVE session.
	if destroyErr != nil {
		t.Fatalf("Destroy inside the commit->bind window = %v; want nil (it addressed a live ACTIVE row)", destroyErr)
	}
	// The create must NOT report success for a session the destroy tombstoned
	// mid-flight: its bind lands on the RELEASED row, refuses, and the pipeline
	// unwinds. A nil error here is the resurrection bug -- the caller would hold
	// a "live" session whose row is a tombstone.
	if createErr == nil {
		t.Fatal("Create returned nil after its session was destroyed mid-flight; want the bind-stage refusal (the row is a RELEASED tombstone)")
	}

	// No orphan: the create's unwind removed the container the destroy's
	// teardown could not address (its row snapshot carried no container name).
	if got := provider.liveCount(); got != 0 {
		t.Fatalf("%d container(s) survive with no live row -- the create's unwind did not reclaim its materialize", got)
	}
	// And no live row: the tombstone is the terminal state.
	live, err := hook.LiveSessions(ctx)
	if err != nil {
		t.Fatalf("LiveSessions: %v", err)
	}
	if len(live) != 0 {
		t.Fatalf("%d live row(s) after the settled destroy-mid-create, want 0", len(live))
	}
}

// TestDestroyInCommitBindWindowKeepsConcurrencyCount pins the slot-ownership
// rule for the same interleaving: the concurrency slot is owned by the CREATE
// from admission until its bind succeeds (then the session owns it) or its
// unwind refunds it. A Destroy that releases a row still unbound (empty
// ContainerName on the released row = the bind had not landed) must NOT
// ReleaseConcurrency -- that refund is still the create's to make via its
// unwind. A destroy that also decremented handed the tenant a double credit:
// with another session legitimately holding a slot, the cell under-counted by
// one (over-admitting a later create). The seeded live session below makes the
// under-count observable -- without it the store's saturate-at-zero would mask
// the double credit.
func TestDestroyInCommitBindWindowKeepsConcurrencyCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	clk := state.NewFakeClock(lifeStart)
	hook := &commitHookStore{listerStore: newListerStore(state.NewInMemory(clk))}
	cust := registry.NewCustodian(hook)
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(hook, clk, generousLimits())

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
	})

	// Seed one live session holding one slot; the hook is not armed yet, so its
	// commit passes through untouched.
	if _, err := mgr.Create(ctx, input("held-session")); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	// Now the destroy-mid-create interleaving on a second hint.
	hook.afterCommit = func() { _ = mgr.Destroy(ctx, testCaller, "destroyed-mid-create-2") }
	if _, err := mgr.Create(ctx, input("destroyed-mid-create-2")); err == nil {
		t.Fatal("Create returned nil after its session was destroyed mid-flight; want the bind-stage refusal")
	}

	// The tenant's cell must still count exactly the seeded live session: the
	// raced create's charge was refunded ONCE (by its own unwind), never twice.
	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: testCaller.Identity}
	level, err := hook.Charge(ctx, concKey, 0, 1<<30)
	if err != nil {
		t.Fatalf("read concurrency cell: %v", err)
	}
	if level != 1 {
		t.Fatalf("concurrency cell = %d, want 1 (the seeded session's slot; a destroy-mid-create must not double-credit the raced create's slot)", level)
	}
}

// TestDoubleDestroyReturnsTheSlotOnce pins the other face of the same
// slot-ownership rule: a REPEATED destroy of an already-RELEASED session tears
// nothing down (the lookup has no state filter, and Release is an idempotent
// no-op on a tombstone), so it must not return the slot a second time. The
// first destroy returned it; a second unconditional decrement hands the tenant
// another credit and under-counts the cell exactly like the mid-create race.
// The seeded live session makes it observable past the saturate-at-zero floor.
func TestDoubleDestroyReturnsTheSlotOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t)

	if _, err := h.mgr.Create(ctx, input("held-session")); err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	if _, err := h.mgr.Create(ctx, input("victim")); err != nil {
		t.Fatalf("victim Create: %v", err)
	}
	if err := h.mgr.Destroy(ctx, testCaller, "victim"); err != nil {
		t.Fatalf("first Destroy: %v", err)
	}
	// The repeat destroy addresses the tombstone: idempotent, and slot-neutral.
	if err := h.mgr.Destroy(ctx, testCaller, "victim"); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}

	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: testCaller.Identity}
	level, err := h.store.Charge(ctx, concKey, 0, 1<<30)
	if err != nil {
		t.Fatalf("read concurrency cell: %v", err)
	}
	if level != 1 {
		t.Fatalf("concurrency cell = %d, want 1 (a repeat destroy of a tombstone must not return the slot again)", level)
	}
}
