// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// kidSet collapses the published PublicKeys into a kid set for membership checks.
func kidSet(keys []cred.PublicKey) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k.KID] = true
	}
	return out
}

// TestRotationOverlap drives the keyset rotation on the monotonic timeline: a
// Rotate keeps BOTH the new active and the just-superseded previous key published
// during the 24h overlap, the previous key drops once monotonic time passes the
// window, and a wall-clock setback never resurrects the dropped key. The newest
// key always mints.
func TestRotationOverlap(t *testing.T) {
	t.Parallel()
	signer, clk := newTestSigner(t, cred.AlgEdDSA, time.Minute)
	ks := signer.KeySet()

	originalKID := signer.ActiveKID()
	if pubs := ks.PublicKeys(); len(pubs) != 1 || !kidSet(pubs)[originalKID] {
		t.Fatalf("pre-rotation: want only original kid %q published, got %v", originalKID, pubs)
	}

	// Rotate to a fresh key; both keys publish during the overlap, the new one
	// mints.
	ks.Rotate(freshEd25519Key(t), cred.AlgEdDSA, "kid-rotated")
	newKID := signer.ActiveKID()
	if newKID != "kid-rotated" {
		t.Fatalf("after rotate: active kid = %q, want kid-rotated", newKID)
	}
	pubs := ks.PublicKeys()
	set := kidSet(pubs)
	if len(pubs) != 2 || !set[originalKID] || !set["kid-rotated"] {
		t.Fatalf("inside overlap: want both kids published, got %v", pubs)
	}

	// Advance to just inside the overlap: both still publish.
	clk.Advance(23 * time.Hour)
	if set := kidSet(ks.PublicKeys()); !set[originalKID] || !set["kid-rotated"] {
		t.Fatalf("23h in: previous key dropped too early: %v", ks.PublicKeys())
	}

	// Advance past the 24h overlap: the previous key drops.
	clk.Advance(2 * time.Hour) // total 25h > 24h
	afterDrop := kidSet(ks.PublicKeys())
	if afterDrop[originalKID] {
		t.Fatalf("past overlap: previous key %q should have dropped: %v", originalKID, ks.PublicKeys())
	}
	if !afterDrop["kid-rotated"] {
		t.Fatalf("past overlap: active key must remain published: %v", ks.PublicKeys())
	}

	// A wall-clock setback far into the past must NOT resurrect the dropped key:
	// the overlap rides the monotonic base, which a setback never moves.
	clk.SetWallClock(testStart.Add(-1000 * time.Hour))
	if kidSet(ks.PublicKeys())[originalKID] {
		t.Fatalf("setback resurrected the dropped previous key: %v", ks.PublicKeys())
	}
}

// TestNeedsRotation exercises the operator/boot rotation seam: a key under the
// 90d horizon does not need rotation, one at or past it does, and a wall-clock
// setback never flips the decision because the horizon rides the monotonic base.
func TestNeedsRotation(t *testing.T) {
	t.Parallel()
	signer, clk := newTestSigner(t, cred.AlgEdDSA, time.Minute)
	ks := signer.KeySet()

	if ks.NeedsRotation() {
		t.Fatal("a fresh key must not need rotation")
	}

	// Just under the horizon: still fine.
	clk.Advance(89 * 24 * time.Hour)
	if ks.NeedsRotation() {
		t.Fatal("a key under the 90d horizon must not need rotation")
	}

	// At the horizon: rotation is due.
	clk.Advance(24 * time.Hour) // total 90d
	if !ks.NeedsRotation() {
		t.Fatal("a key at the 90d horizon must need rotation")
	}

	// A wall-clock setback must not defer the (already-due) rotation.
	clk.SetWallClock(testStart)
	if !ks.NeedsRotation() {
		t.Fatal("a wall-clock setback must not defer a due rotation")
	}
}
