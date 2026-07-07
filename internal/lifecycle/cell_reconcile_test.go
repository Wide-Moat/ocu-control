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

// TestReconcile_HealsConcurrencyCellDrift is the Finding #4 keystone. The
// DimConcurrentSessions quota cell is a separate lock domain from the reservation
// rows, charged +1 at create and refunded -1 on unwind/destroy/reclaim. If a refund
// is lost — a create aborts and the unwind's Receipt.Apply fails against a bad
// connection, and the unwind swallows that error — the cell drifts ABOVE the true
// live-row count with no row to reclaim. The row-based reconciler (substrate-lost)
// never corrects it because there is no leaked row, only a leaked counter. Over time
// the cell climbs to the tier cap and every later create is refused ErrQuotaExceeded
// against a phantom count, with zero live sessions — a persistent wedge a restart
// must clear.
//
// The boot reconciler now heals the drift: it recomputes DimConcurrentSessions from
// the actual live (RESERVED+ACTIVE) rows per tenant and corrects the cell down to the
// true count. This test seeds one live ACTIVE row, inflates the cell to 5 (four
// phantom charges), reconciles, and asserts the cell falls to 1 (the true live
// count). Skip the cell-reconcile and the cell stays inflated — this reds.
func TestReconcile_HealsConcurrencyCellDrift(t *testing.T) {
	t.Parallel()
	mgr, store, provider := newShippedManager(t)
	ctx := context.Background()
	owner := testCaller.Identity

	// One genuinely live ACTIVE session: the true concurrency count is 1.
	key := registry.DeriveKey(owner, "live-session")
	if _, err := store.Reserve(ctx, key.String(), owner); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	if _, err := store.Commit(ctx, key.String(), owner); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	// The diff-based reconciler counts a row as live only when its container is present
	// AND running in the pre-sweep snapshot; seed a matching Alive container so the live
	// ACTIVE row is recognised as live (else Direction 2 reclaims it and the cell heals
	// to 0, not the true count under test here).
	provider.reconcileOrphans = []runtime.Sandbox{{Name: runtime.SessionName(key.String()), Alive: true}}

	// Inflate the concurrency cell to 5 — one honest charge for the live row plus four
	// phantom charges that model refunds lost to swallowed unwind errors on aborted
	// creates.
	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
	if _, err := store.Charge(ctx, concKey, 5, 1000); err != nil {
		t.Fatalf("seed inflated cell: %v", err)
	}
	if got := concurrentCount(t, store, owner); got != 5 {
		t.Fatalf("pre-reconcile cell = %d, want 5 (inflated)", got)
	}

	if err := mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The cell is healed down to the true live-row count: one live ACTIVE session.
	if got := concurrentCount(t, store, owner); got != 1 {
		t.Fatalf("post-reconcile cell = %d, want 1 (healed to the live-row count)", got)
	}
}

// TestReconcile_CellDriftHealDoesNotUndercount is the paired guard: the heal only
// CORRECTS DOWN a drifted cell — it must never charge the cell UP or drive it below
// the true live count. A cell already equal to the live-row count is left untouched.
func TestReconcile_CellDriftHealDoesNotUndercount(t *testing.T) {
	t.Parallel()
	mgr, store, provider := newShippedManager(t)
	ctx := context.Background()
	owner := testCaller.Identity

	// Two live ACTIVE sessions and a cell that already reads exactly 2 (no drift). Each
	// gets a matching Alive container in the snapshot so the diff-based reconciler counts
	// both as live and leaves the already-correct cell untouched.
	var liveSnapshot []runtime.Sandbox
	for _, h := range []string{"s1", "s2"} {
		key := registry.DeriveKey(owner, h)
		if _, err := store.Reserve(ctx, key.String(), owner); err != nil {
			t.Fatalf("seed reserve %s: %v", h, err)
		}
		if _, err := store.Commit(ctx, key.String(), owner); err != nil {
			t.Fatalf("seed commit %s: %v", h, err)
		}
		liveSnapshot = append(liveSnapshot, runtime.Sandbox{Name: runtime.SessionName(key.String()), Alive: true})
	}
	provider.reconcileOrphans = liveSnapshot
	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
	if _, err := store.Charge(ctx, concKey, 2, 1000); err != nil {
		t.Fatalf("seed matching cell: %v", err)
	}

	if err := mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The cell already matched the live count: the heal leaves it at 2, never inflating
	// or undercounting.
	if got := concurrentCount(t, store, owner); got != 2 {
		t.Fatalf("post-reconcile cell = %d, want 2 (matched, untouched)", got)
	}
}
