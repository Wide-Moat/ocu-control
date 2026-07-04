// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// newShippedManager builds a Manager over the BARE shipped in-memory store — NOT
// the test listerStore wrapper — so the boot-reconcile path drives the real
// LiveSessions implementation. This is the regression guard for the boot-unblock:
// before the shipped store implemented LiveSessions, mgr.Reconcile returned
// registry.ErrEnumerationUnsupported and the daemon died on a healthy host.
func newShippedManager(t *testing.T) (*lifecycle.Manager, state.Store, *recordingProvider) {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := state.NewInMemory(clk)
	cust := registry.NewCustodian(store)
	provider := newRecordingProvider()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, generousLimits()),
		Handoff:       newFaultStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		ExecVerifyKey: pub32(),
	})
	return mgr, store, provider
}

// TestReconcile_ShippedInMemoryStore_CleanHostSucceeds proves the boot-unblock: a
// Manager over the bare shipped in-memory store reconciles to nil on a clean host
// (no orphans), so the boot readiness hook proceeds to bind both listeners instead
// of aborting on ErrEnumerationUnsupported. This is exactly the onReady step the
// daemon runs at boot.
func TestReconcile_ShippedInMemoryStore_CleanHostSucceeds(t *testing.T) {
	t.Parallel()
	mgr, _, _ := newShippedManager(t)
	if err := mgr.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile over the shipped in-memory store on a clean host must succeed, got: %v", err)
	}
}

// TestReconcile_ShippedInMemoryStore_ReclaimsCrashedReserved proves the reconcile
// reclaim actually drives off the shipped LiveSessions: a crashed-mid-create
// RESERVED row (reserved, never committed) is enumerated by LiveSessions, released
// to the tombstone, and its concurrent slot returned. An ACTIVE row is a live
// session and is left alone.
func TestReconcile_ShippedInMemoryStore_ReclaimsCrashedReserved(t *testing.T) {
	t.Parallel()
	mgr, store, _ := newShippedManager(t)
	ctx := context.Background()
	owner := testCaller.Identity

	// A crashed create leaves a bare RESERVED row plus a charged concurrent slot.
	crashed := registry.DeriveKey(owner, "crashed-handle")
	if _, err := store.Reserve(ctx, crashed.String(), owner); err != nil {
		t.Fatalf("seed crashed RESERVED row: %v", err)
	}
	if _, err := store.Charge(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}, 1, 64); err != nil {
		t.Fatalf("seed concurrent charge: %v", err)
	}

	if err := mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The crashed RESERVED row is reclaimed to the RELEASED tombstone.
	row, err := store.LookupSession(ctx, crashed.String())
	if err != nil {
		t.Fatalf("lookup after reconcile: %v", err)
	}
	if row.State != state.StateReleased {
		t.Fatalf("crashed RESERVED row must be reclaimed to RELEASED, got %v", row.State)
	}
	// The concurrent slot is returned (the level counter falls back to zero).
	got := concurrentCount(t, store, owner)
	if got != 0 {
		t.Fatalf("reconcile must return the crashed session's concurrent slot, counter = %d, want 0", got)
	}
}
