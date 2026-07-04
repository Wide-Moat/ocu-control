// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestRace_CreateVsDestroySameKey drives a concurrent Create and Destroy on the
// SAME session key through the real lifecycle.Manager, under -race, over many
// rounds. The state-layer advisory lock is already proven at the store primitive
// (internal/state/race_test.go); this closes the gap the coverage map named — the
// PIPELINE-composition race: reserve→…→bind (Create) vs lookup→audit→teardown→
// release (Destroy) contending on one key through the Manager, not just the Store.
//
// The invariant is that NO round leaves torn state and NO data race fires:
//   - the race detector sees no unsynchronised access across the Create/Destroy
//     pipelines (the whole point of running under -race);
//   - every round's terminal row is a LEGAL outcome — ACTIVE (Create won and
//     Destroy either ran before the row existed or after it was rebuilt),
//     RELEASED (Destroy tore down a committed row), or absent/not-owned (Destroy
//     raced ahead of Create) — never a stuck RESERVED row and never a panic;
//   - the provider holds no orphaned container after each round settles (every
//     Materialize is matched by a finalizer, or the create unwound its own).
//
// Neuter check (keystone): the reservation mutators guard the shared row map
// with rowMu (under the per-key advisory stripe). Dropping that map lock — the
// exact synchronisation this exercises — makes -race report a concurrent map
// access between the contending Create and Destroy, reddening this test. It is
// the pipeline-level companion to the store-level race tests.
func TestRace_CreateVsDestroySameKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const rounds = 200
	const hint = "raced-session"

	for r := 0; r < rounds; r++ {
		h := newHarness(t)

		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})

		// Create pipeline.
		go func() {
			defer wg.Done()
			<-start
			// A create may win (row ACTIVE) or lose to a torn intermediate; either
			// way it must never panic and must return a typed result. We do not
			// assert which side wins — only that the composition is race-free and
			// terminates in a legal state, checked after the barrier.
			_, _ = h.mgr.Create(ctx, input(hint))
		}()

		// Destroy pipeline on the same key.
		go func() {
			defer wg.Done()
			<-start
			err := h.mgr.Destroy(ctx, testCaller, hint)
			// A destroy that raced ahead of the create sees ErrNotOwned (absent /
			// not-yet-reserved is indistinguishable from not-owned by design); a
			// destroy that landed after commit returns nil. Any OTHER error is a
			// torn-composition bug.
			if err != nil && !errors.Is(err, registry.ErrNotOwned) {
				t.Errorf("round %d: Destroy returned an unexpected error %v; want nil or registry.ErrNotOwned on a create/destroy race", r, err)
			}
		}()

		close(start)
		wg.Wait()

		// LiveSessions returns only RESERVED/ACTIVE rows (RELEASED tombstones are
		// filtered out), so after the race settles it holds at most one row for the
		// single contended key. A stuck RESERVED row is the torn-composition failure:
		// a create that reserved but neither committed nor released, or a half-run
		// destroy. Zero live rows is legal (destroy won, or the create fully unwound).
		live, err := h.store.LiveSessions(ctx)
		if err != nil {
			t.Fatalf("round %d: LiveSessions after the race = %v", r, err)
		}
		if len(live) > 1 {
			t.Fatalf("round %d: %d live rows for one key — the race produced duplicate reservations", r, len(live))
		}
		activeRows := 0
		for _, row := range live {
			if row.State == state.StateReserved {
				t.Fatalf("round %d: a settled row is stuck in RESERVED — a torn create/destroy composition (reserved but never committed, never released)", r)
			}
			if row.State == state.StateActive {
				activeRows++
			}
		}

		// No container may be orphaned once the round settles: an ACTIVE row owns
		// exactly one live container; no ACTIVE row means none survive (the finalizer
		// tore it down, or the create unwound its own partial materialize).
		gotLive := h.provider.liveCount()
		if activeRows == 1 && gotLive != 1 {
			t.Fatalf("round %d: an ACTIVE row must own exactly 1 live container, got %d", r, gotLive)
		}
		if activeRows == 0 && gotLive != 0 {
			t.Fatalf("round %d: %d container(s) orphaned with no ACTIVE row — the finalizer or the create unwind leaked a container", r, gotLive)
		}
	}
}
