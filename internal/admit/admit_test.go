// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package admit_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admit"
)

// TestReservedPriority_RevokeAdmitsWhileGeneralIsSaturated is the SEC-55 keystone:
// with every GENERAL slot held by an in-flight flood, a PRIORITY (revoke) request
// still admits immediately from the reserved sub-pool — a create/read flood on the
// operator socket cannot starve the revoke route. A general request in the same
// saturated state does NOT admit (it has no reserved slots to draw on), proving the
// reservation is what let the priority request through, not spare general capacity.
func TestReservedPriority_RevokeAdmitsWhileGeneralIsSaturated(t *testing.T) {
	t.Parallel()
	// 2 general slots, 1 reserved for priority.
	g := admit.NewGate(2, 1)

	// Saturate every general slot and hold them (never release during the test).
	for i := 0; i < 2; i++ {
		rel, ok := g.Acquire(context.Background(), admit.ClassGeneral)
		if !ok {
			t.Fatalf("general acquire %d refused while slots free", i)
		}
		defer rel()
	}

	// A general request now finds no slot within a short deadline: it must NOT admit.
	genCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if rel, ok := g.Acquire(genCtx, admit.ClassGeneral); ok {
		rel()
		t.Fatal("a general request admitted while every general slot was held; the flood is not bounded")
	}

	// A PRIORITY request admits immediately from the reserved sub-pool despite the
	// general saturation — this is the reservation doing its job.
	prCtx, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	rel, ok := g.Acquire(prCtx, admit.ClassPriority)
	if !ok {
		t.Fatal("a priority (revoke) request was starved by a general flood — SEC-55 violated")
	}
	rel()
}

// TestReservedPriority_PriorityFallsBackToGeneralWhenReservedFull pins that once the
// reserved pool is exhausted, an additional priority request may still use a free
// general slot — the reservation is a floor for priority, not a ceiling.
func TestReservedPriority_PriorityFallsBackToGeneralWhenReservedFull(t *testing.T) {
	t.Parallel()
	g := admit.NewGate(1, 1) // 1 general, 1 reserved

	// Take the single reserved slot with a priority request.
	rel1, ok := g.Acquire(context.Background(), admit.ClassPriority)
	if !ok {
		t.Fatal("first priority acquire refused with a free reserved slot")
	}
	defer rel1()

	// A second priority request finds the reserved pool empty but a general slot free
	// — it must fall back to general and admit.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	rel2, ok := g.Acquire(ctx, admit.ClassPriority)
	if !ok {
		t.Fatal("second priority request did not fall back to a free general slot")
	}
	rel2()
}

// TestGate_ReleaseReturnsTheSlot proves a released slot is reusable: acquire to
// saturation, release one, and the next acquire of that class succeeds.
func TestGate_ReleaseReturnsTheSlot(t *testing.T) {
	t.Parallel()
	g := admit.NewGate(1, 0)

	rel, ok := g.Acquire(context.Background(), admit.ClassGeneral)
	if !ok {
		t.Fatal("first general acquire refused with a free slot")
	}
	// Saturated now; a non-blocking check refuses.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if _, ok := g.Acquire(ctx, admit.ClassGeneral); ok {
		cancel()
		t.Fatal("acquired a second slot on a size-1 general pool")
	}
	cancel()
	rel() // return the slot
	// Now it must admit again.
	rel2, ok := g.Acquire(context.Background(), admit.ClassGeneral)
	if !ok {
		t.Fatal("general slot was not returned on release")
	}
	rel2()
}

// TestGate_ConcurrentAcquireNeverExceedsCapacity is the race/invariant guard: N
// goroutines contend for a bounded gate; the number simultaneously holding a slot
// never exceeds general+reserved. Run under -race.
func TestGate_ConcurrentAcquireNeverExceedsCapacity(t *testing.T) {
	t.Parallel()
	const general, reserved = 4, 2
	g := admit.NewGate(general, reserved)

	var (
		mu      sync.Mutex
		held    int
		maxHeld int
	)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			class := admit.ClassGeneral
			if i%3 == 0 {
				class = admit.ClassPriority
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			rel, ok := g.Acquire(ctx, class)
			if !ok {
				return
			}
			mu.Lock()
			held++
			if held > maxHeld {
				maxHeld = held
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			held--
			mu.Unlock()
			rel()
		}(i)
	}
	wg.Wait()

	if maxHeld > general+reserved {
		t.Fatalf("max concurrent holders %d exceeded capacity %d", maxHeld, general+reserved)
	}
}
