// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package registry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestEnrichedLiveSessionsAndRecordActivation proves the Custodian routes the admin
// read-surface read+write through the Store's optional EnrichedLister /
// ActivationRecorder seams: RecordActivation stamps the activation enrichment onto
// a committed row, and EnrichedLiveSessions reads it back with the reserved-at
// always present and the active-at/caps appearing only after the record.
func TestEnrichedLiveSessionsAndRecordActivation(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	ctx := context.Background()
	owner := state.Identity{Tenant: "t", Caller: "c"}

	reserved := registry.DeriveKey(owner, "handle-reserved")
	active := registry.DeriveKey(owner, "handle-active")
	if _, err := c.Reserve(ctx, reserved, owner); err != nil {
		t.Fatalf("Reserve reserved: %v", err)
	}
	if _, err := c.Reserve(ctx, active, owner); err != nil {
		t.Fatalf("Reserve active: %v", err)
	}
	if _, err := c.Commit(ctx, active, owner); err != nil {
		t.Fatalf("Commit active: %v", err)
	}

	pids := int64(128)
	caps := state.Caps{CPUCores: 2, MemoryBytes: 1 << 30, PidsLimit: &pids}
	if err := c.RecordActivation(ctx, active, caps, regStart.Add(7)); err != nil {
		t.Fatalf("RecordActivation: %v", err)
	}

	rows, err := c.EnrichedLiveSessions(ctx)
	if err != nil {
		t.Fatalf("EnrichedLiveSessions: %v", err)
	}
	byKey := make(map[string]state.EnrichedSessionRow, len(rows))
	for _, r := range rows {
		byKey[r.Key] = r
	}
	if len(byKey) != 2 {
		t.Fatalf("want 2 live enriched rows, got %d", len(byKey))
	}

	// The reserved (never-recorded) row: reserved-at present, no active-at/caps.
	res := byKey[reserved.String()]
	if res.ReservedAt.IsZero() {
		t.Errorf("reserved row must carry reserved-at")
	}
	if res.ActiveAt != nil || res.Caps != nil {
		t.Errorf("never-recorded row must have nil active-at/caps, got %+v", res)
	}

	// The recorded active row: active-at + caps present.
	act := byKey[active.String()]
	if act.ActiveAt == nil {
		t.Fatalf("recorded row must carry active-at")
	}
	if act.Caps == nil || act.Caps.PidsLimit == nil || *act.Caps.PidsLimit != pids {
		t.Errorf("recorded row caps: want pids %d, got %+v", pids, act.Caps)
	}
}

// TestEnrichedLiveSessionsUnsupported proves the fail-closed branch: a Store that
// does NOT implement EnrichedLister yields ErrEnumerationUnsupported (not an empty
// slice), so the read-API surfaces it rather than reporting a guessed-empty set.
// The nonListerStore shim embeds the state.Store interface, which does not promote
// the in-memory leg's optional seam methods, so it stands in for a Store without the
// capability.
func TestEnrichedLiveSessionsUnsupported(t *testing.T) {
	t.Parallel()
	inner := state.NewInMemory(state.NewFakeClock(regStart))
	c := registry.NewCustodian(&nonListerStore{Store: inner})
	if _, err := c.EnrichedLiveSessions(context.Background()); !errors.Is(err, registry.ErrEnumerationUnsupported) {
		t.Fatalf("EnrichedLiveSessions on a non-enriching Store: error %v, want ErrEnumerationUnsupported", err)
	}
}

// TestRecordActivationUnsupported proves RecordActivation on a Store without the
// ActivationRecorder seam returns ErrEnumerationUnsupported, which the caller
// treats the same non-fatal way (the read surface simply lacks the enrichment).
func TestRecordActivationUnsupported(t *testing.T) {
	t.Parallel()
	inner := state.NewInMemory(state.NewFakeClock(regStart))
	c := registry.NewCustodian(&nonListerStore{Store: inner})
	owner := state.Identity{Tenant: "t", Caller: "c"}
	key := registry.DeriveKey(owner, "h")
	if err := c.RecordActivation(context.Background(), key, state.Caps{}, regStart); !errors.Is(err, registry.ErrEnumerationUnsupported) {
		t.Fatalf("RecordActivation on a non-recording Store: error %v, want ErrEnumerationUnsupported", err)
	}
}

// TestTouchActivityRoutesToStore proves the Custodian routes TouchActivity through the
// Store's optional ActivityToucher seam: touching a committed row advances its
// last-activity stamp, and EnrichedLiveSessions reads the new stamp back. This is the
// activity-tracking seam the idle reaper measures idleness against — a touch must land
// on the enrichment, and the touched instant is the one the read surface reports (never
// a persisted-timestamp round-trip, so the reaper compares two in-process Clock reads).
func TestTouchActivityRoutesToStore(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	ctx := context.Background()
	owner := state.Identity{Tenant: "t", Caller: "c"}

	key := registry.DeriveKey(owner, "handle-touch")
	if _, err := c.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := c.Commit(ctx, key, owner); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// RecordActivation seeds the initial stamp; a later TouchActivity must advance it.
	if err := c.RecordActivation(ctx, key, state.Caps{CPUCores: 1}, regStart.Add(5)); err != nil {
		t.Fatalf("RecordActivation: %v", err)
	}
	touchAt := regStart.Add(100)
	if err := c.TouchActivity(ctx, key, touchAt); err != nil {
		t.Fatalf("TouchActivity: %v", err)
	}

	rows, err := c.EnrichedLiveSessions(ctx)
	if err != nil {
		t.Fatalf("EnrichedLiveSessions: %v", err)
	}
	var got *state.EnrichedSessionRow
	for i := range rows {
		if rows[i].Key == key.String() {
			got = &rows[i]
			break
		}
	}
	if got == nil {
		t.Fatal("touched row not enumerated")
	}
	if got.LastActivity == nil {
		t.Fatal("touched row has nil LastActivity — the touch did not route to the Store")
	}
	if !got.LastActivity.Equal(touchAt) {
		t.Fatalf("LastActivity = %v, want the touched instant %v (the touch must advance the stamp)", *got.LastActivity, touchAt)
	}
}

// TestTouchActivityUnsupported proves TouchActivity on a Store without the
// ActivityToucher seam returns ErrEnumerationUnsupported. The exec path swallows this
// (a touch failure is non-fatal — the session keeps its prior stamp), but the Custodian
// still surfaces the typed error rather than silently reporting success, so a Store that
// cannot track activity is distinguishable from one that did.
func TestTouchActivityUnsupported(t *testing.T) {
	t.Parallel()
	inner := state.NewInMemory(state.NewFakeClock(regStart))
	c := registry.NewCustodian(&nonListerStore{Store: inner})
	owner := state.Identity{Tenant: "t", Caller: "c"}
	key := registry.DeriveKey(owner, "h")
	if err := c.TouchActivity(context.Background(), key, regStart); !errors.Is(err, registry.ErrEnumerationUnsupported) {
		t.Fatalf("TouchActivity on a non-touching Store: error %v, want ErrEnumerationUnsupported", err)
	}
}
