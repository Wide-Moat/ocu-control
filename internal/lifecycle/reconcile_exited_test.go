// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestReconcile_ExitedButPresentContainer_ReclaimsSlotAndSweeps is the F-2 keystone.
// The boot reconciler lists every managed container regardless of run-state
// (ListOptions{All:true}), so an Exited-but-present container appears in the live
// snapshot. Before the fix, Direction-2 skipped the reclaim for any row whose name
// was present in that snapshot (liveByName[key].Name != ""), so an ACTIVE row whose
// container had EXITED but not yet been removed kept its concurrency slot forever —
// the counter wedged the tier cap with no running session behind it. Direction-1
// likewise skipped the force-kill for a container matched to a row, leaving the dead
// container as garbage.
//
// The fix reads Sandbox.Alive: a present-but-!Alive container is substrate-lost.
// Direction-2 reclaims its row (returning the slot); Direction-1 force-kills it
// (sweeping the garbage) — neither the slot nor the container leaks. This test seeds
// an ACTIVE row plus a charged slot, presents the matching container as Exited
// (Alive:false), and asserts the row is reclaimed, the slot returns to zero, and the
// dead container is swept. Treat every present container as live (drop the Alive
// gate) and the slot stays charged — this reds.
func TestReconcile_ExitedButPresentContainer_ReclaimsSlotAndSweeps(t *testing.T) {
	t.Parallel()
	mgr, store, provider := newShippedManager(t)
	ctx := context.Background()
	owner := testCaller.Identity

	// Seed an ACTIVE row (reserved then committed) plus its charged concurrency slot —
	// a fully-created session holding one tier slot.
	key := registry.DeriveKey(owner, "exited-session")
	if _, err := store.Reserve(ctx, key.String(), owner); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	if _, err := store.Commit(ctx, key.String(), owner); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	if _, err := store.Charge(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}, 1, 64); err != nil {
		t.Fatalf("seed concurrent charge: %v", err)
	}

	// Present the matching container as EXITED-but-present: same session Name as the
	// row, a live RuntimeID the provider still holds, Alive:false (run-state exited).
	name := runtime.SessionName(key.String())
	provider.mu.Lock()
	provider.live["ctr-exited"] = true
	provider.reconcileOrphans = []runtime.Sandbox{{
		Name:      name,
		RuntimeID: "ctr-exited",
		Alive:     false, // exited, not running/restarting
	}}
	provider.mu.Unlock()

	if err := mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The ACTIVE row whose container has exited is reclaimed to the RELEASED tombstone.
	row, err := store.LookupSession(ctx, key.String())
	if err != nil {
		t.Fatalf("lookup after reconcile: %v", err)
	}
	if row.State != state.StateReleased {
		t.Fatalf("ACTIVE row with an exited container must be reclaimed to RELEASED, got %v", row.State)
	}
	// The concurrency slot is returned — the whole point: a dead-but-present container
	// no longer wedges the tier cap.
	if got := concurrentCount(t, store, owner); got != 0 {
		t.Fatalf("reconcile must return the exited session's slot, counter = %d, want 0", got)
	}
	// The dead container was force-killed (swept), so the fix leaks no container
	// garbage either: the provider no longer holds it.
	if provider.liveCount() != 0 {
		t.Fatalf("the exited container must be force-killed (swept), provider still holds %d", provider.liveCount())
	}
}

// TestReconcile_RunningContainer_KeepsSlot is the paired guard: an ACTIVE row whose
// container is genuinely RUNNING (Alive:true) must NOT be reclaimed and its slot must
// stay charged — the Alive gate must not over-reclaim live sessions. Without this a
// too-eager fix (reclaim every matched row) would silently tear down running work.
func TestReconcile_RunningContainer_KeepsSlot(t *testing.T) {
	t.Parallel()
	mgr, store, provider := newShippedManager(t)
	ctx := context.Background()
	owner := testCaller.Identity

	key := registry.DeriveKey(owner, "running-session")
	if _, err := store.Reserve(ctx, key.String(), owner); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	if _, err := store.Commit(ctx, key.String(), owner); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	if _, err := store.Charge(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}, 1, 64); err != nil {
		t.Fatalf("seed concurrent charge: %v", err)
	}

	name := runtime.SessionName(key.String())
	provider.mu.Lock()
	provider.live["ctr-running"] = true
	provider.reconcileOrphans = []runtime.Sandbox{{
		Name:      name,
		RuntimeID: "ctr-running",
		Alive:     true, // running: a live session
	}}
	provider.mu.Unlock()

	if err := mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The running session's row stays ACTIVE and its slot stays charged.
	row, err := store.LookupSession(ctx, key.String())
	if err != nil {
		t.Fatalf("lookup after reconcile: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("running session's row must stay ACTIVE, got %v", row.State)
	}
	if got := concurrentCount(t, store, owner); got != 1 {
		t.Fatalf("running session must keep its slot, counter = %d, want 1", got)
	}
	// The running container is untouched (not force-killed).
	if provider.liveCount() != 1 {
		t.Fatalf("running container must be left alone, provider holds %d, want 1", provider.liveCount())
	}
}
