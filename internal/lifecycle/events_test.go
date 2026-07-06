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

// recordingPublisher is a test lifecycle.EventPublisher: it captures every
// published delta so a test can assert the Manager emitted the live-view
// transitions. It is concurrency-safe so it can be driven under -race.
type recordingPublisher struct {
	mu     sync.Mutex
	events []lifecycle.LifecycleEvent
}

func (p *recordingPublisher) Publish(_ context.Context, ev lifecycle.LifecycleEvent) {
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
}

func (p *recordingPublisher) snapshot() []lifecycle.LifecycleEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]lifecycle.LifecycleEvent, len(p.events))
	copy(out, p.events)
	return out
}

// newManagerWithPublisher builds a Manager wired with pub as its event publisher.
func newManagerWithPublisher(t *testing.T, pub lifecycle.EventPublisher) *lifecycle.Manager {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := newListerStore(state.NewInMemory(clk))
	cust := registry.NewCustodian(store)
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())

	return lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      newRecordingProvider(),
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
		Events:        pub,
	})
}

// TestEventsPublishedOnCreateAndDestroy proves the Manager publishes a live-view
// delta to the design-fenced fan-out: an ACTIVE delta on create-success and a
// RELEASED delta on destroy-success, each carrying the host-derived session key and
// a non-zero transition instant. This is the seam the admin console's SSE consumer
// reads once the wire schema freezes; the polling GET endpoints carry the live view
// until then.
func TestEventsPublishedOnCreateAndDestroy(t *testing.T) {
	t.Parallel()
	pub := &recordingPublisher{}
	mgr := newManagerWithPublisher(t, pub)
	ctx := context.Background()

	row, err := mgr.Create(ctx, input("sess"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	events := pub.snapshot()
	if len(events) != 2 {
		t.Fatalf("published delta count = %d; want exactly 2 (ACTIVE on create, RELEASED on destroy): %+v", len(events), events)
	}

	live := events[0]
	if live.State != state.StateActive {
		t.Errorf("first delta state = %v; want StateActive (the live transition)", live.State)
	}
	if live.Key != row.Key {
		t.Errorf("live delta key = %q; want the created row key %q", live.Key, row.Key)
	}
	if live.At.IsZero() {
		t.Errorf("live delta carries a zero transition instant; want the clock time")
	}

	gone := events[1]
	if gone.State != state.StateReleased {
		t.Errorf("second delta state = %v; want StateReleased (the destroy transition)", gone.State)
	}
	if gone.Key != row.Key {
		t.Errorf("released delta key = %q; want the destroyed row key %q", gone.Key, row.Key)
	}
}

// TestEventsNilPublisherIsCleanNoOp proves the pipeline runs with a nil publisher —
// the publish call is guarded, so a deployment without a fan-out hub (the live
// console polling the GET endpoints) is unaffected.
func TestEventsNilPublisherIsCleanNoOp(t *testing.T) {
	t.Parallel()
	mgr := newManagerWithPublisher(t, nil)
	ctx := context.Background()
	if _, err := mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create with nil publisher: %v", err)
	}
	if err := mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy with nil publisher: %v", err)
	}
}
