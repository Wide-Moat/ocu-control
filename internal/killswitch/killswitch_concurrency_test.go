// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package killswitch_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// concKeyFor is the per-tenant concurrent-session level cell the create path charges
// (+1) and every release path must refund (-1). It is the level dimension, so the
// window is empty per the Store contract.
func concKeyFor(id state.Identity) state.QuotaKey {
	return state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id, Window: ""}
}

// TestRevokeAllRefundsConcurrencySlot is the F-1 keystone: a force-killed row must
// return its per-tenant DimConcurrentSessions slot, exactly as lifecycle.Destroy and
// the boot reconciler do. Before the fix, forceKillRow drove the row to the RELEASED
// tombstone (ForceReleaseRow) but never called the concurrency refund, so the level
// counter was a write-only ratchet on the kill path: after an emergency RevokeAll the
// tenant's slot stayed charged with zero live rows, and every later create was refused
// ErrQuotaExceeded against a phantom count. This test charges the counter through the
// real quota.Gate (the create path), force-kills via RevokeAll, and asserts the slot
// is returned. Neuter the refund in forceKillRow and the post-kill count stays at 1 —
// this reds.
func TestRevokeAllRefundsConcurrencySlot(t *testing.T) {
	t.Parallel()
	h := newEngineHarness()
	ctx := context.Background()

	// Charge the concurrency counter exactly as the create path does — through the
	// SAME real quota.Gate the engine refunds through, over the same Store, no mock.
	// This is the +1 that every release path owes a matching -1; asserting the SAME
	// Gate returns it on force-kill is the whole point.
	if _, err := h.gate.ChargeCreate(ctx, owner); err != nil {
		t.Fatalf("charge create: %v", err)
	}
	if got := readConc(t, h.store, owner); got != 1 {
		t.Fatalf("pre-kill concurrency count = %d, want 1", got)
	}

	// Seed the matching RESERVED row so RevokeAll has a live row to force-kill.
	h.reserveRow(t, "charged-session")

	if err := h.engine.RevokeAll(ctx, h.scope, "incident-slot"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	// The force-kill returned the slot: the level counter is back to zero, so a fresh
	// tenant create is admitted against the true (empty) live count, not a phantom one.
	if got := readConc(t, h.store, owner); got != 0 {
		t.Fatalf("post-kill concurrency count = %d, want 0 — the force-kill did not refund the slot (write-only ratchet)", got)
	}
}

// readConc reads the per-tenant concurrent-session level cell without mutating it.
func readConc(t *testing.T, store state.Store, id state.Identity) int64 {
	t.Helper()
	v, err := store.ReadQuota(context.Background(), concKeyFor(id))
	if err != nil {
		t.Fatalf("read concurrency quota: %v", err)
	}
	return v
}
