// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

var replayStart = time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)

func rfc3339(t time.Time) string { return t.Format(time.RFC3339) }

// TestReplayGuardAcceptsAFreshIssuance is the baseline the refusals are read
// against: a first presentation inside the window passes.
func TestReplayGuardAcceptsAFreshIssuance(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	g := newReplayGuard(clk, 300*time.Second)

	if err := g.admit(rfc3339(replayStart), []byte("sig-a")); err != nil {
		t.Errorf("a fresh issuance inside the window was refused: %v", err)
	}
}

// TestReplayGuardRefusesTheSameSignatureTwice is the replay case itself. The
// cache is keyed on the signature bytes: Ed25519 is deterministic, so a replay
// of a revoke is byte-identical and keys cleanly.
func TestReplayGuardRefusesTheSameSignatureTwice(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	g := newReplayGuard(clk, 300*time.Second)
	issued := rfc3339(replayStart)

	if err := g.admit(issued, []byte("sig-a")); err != nil {
		t.Fatalf("first presentation refused: %v", err)
	}
	err := g.admit(issued, []byte("sig-a"))
	if err == nil {
		t.Fatal("the SAME signature was admitted twice — a captured revoke could be " +
			"re-presented for as long as its issued_at stays inside the window")
	}
	if !errors.Is(err, errReplayed) {
		t.Errorf("error %v does not wrap errReplayed; the 409 response keys on it", err)
	}
}

// TestReplayGuardRefusesOutsideTheWindow covers both edges. A stale issuance is
// the captured-and-held case; a future-dated one is what a caller with a skewed
// or hostile clock presents to buy itself a longer replay window.
func TestReplayGuardRefusesOutsideTheWindow(t *testing.T) {
	cases := []struct {
		name   string
		offset time.Duration
		admit  bool
	}{
		{name: "at the stale edge", offset: -300 * time.Second, admit: true},
		{name: "one second beyond stale", offset: -301 * time.Second},
		{name: "at the future edge", offset: 300 * time.Second, admit: true},
		{name: "one second beyond future", offset: 301 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := state.NewFakeClock(replayStart)
			g := newReplayGuard(clk, 300*time.Second)

			err := g.admit(rfc3339(replayStart.Add(tc.offset)), []byte("sig-a"))
			switch {
			case tc.admit && err != nil:
				t.Errorf("an issuance exactly at the window edge was refused: %v — the "+
					"bound is inclusive, so a legitimate revoke at the limit must pass", err)
			case !tc.admit && err == nil:
				t.Error("an issuance outside the acceptance window was admitted")
			case !tc.admit && !errors.Is(err, errOutsideWindow):
				t.Errorf("error %v does not wrap errOutsideWindow; the 409 keys on it", err)
			}
		})
	}
}

// TestReplayGuardRefusesAnUnparseableIssuedAt fails closed on a timestamp it
// cannot read. Admitting one would skip the window check entirely, which is the
// cheapest possible bypass of the whole guard.
func TestReplayGuardRefusesAnUnparseableIssuedAt(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	g := newReplayGuard(clk, 300*time.Second)

	for _, bad := range []string{"", "not-a-time", "2026-08-07", "1754560800"} {
		if err := g.admit(bad, []byte("sig-a")); err == nil {
			t.Errorf("admitted an unparseable issued_at %q — the window check cannot "+
				"run on it, so admitting skips the guard", bad)
		}
	}
}

// TestReplayGuardForgetsEntriesOnceTheyLeaveTheWindow keeps the cache bounded.
// An entry whose issuance can no longer be admitted on window grounds carries no
// information, so retaining it would grow memory without buying protection.
func TestReplayGuardForgetsEntriesOnceTheyLeaveTheWindow(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	g := newReplayGuard(clk, 300*time.Second)

	for i := 0; i < 50; i++ {
		if err := g.admit(rfc3339(clk.Now()), []byte{byte(i)}); err != nil {
			t.Fatalf("presentation %d refused: %v", i, err)
		}
		clk.Advance(time.Second)
	}
	// Every entry above is now older than the window.
	clk.Advance(400 * time.Second)
	if err := g.admit(rfc3339(clk.Now()), []byte("fresh")); err != nil {
		t.Fatalf("fresh issuance refused: %v", err)
	}
	if n := g.size(); n > 1 {
		t.Errorf("cache holds %d entries after every earlier one left the window; "+
			"entries that can no longer be admitted on window grounds must be "+
			"dropped or the cache grows without bound", n)
	}
}

// TestReplayGuardDistinguishesSignatures pins that the cache keys on the
// signature rather than only the timestamp. Two distinct revokes issued in the
// same second are both legitimate.
func TestReplayGuardDistinguishesSignatures(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	g := newReplayGuard(clk, 300*time.Second)
	issued := rfc3339(replayStart)

	if err := g.admit(issued, []byte("sig-a")); err != nil {
		t.Fatalf("first revoke refused: %v", err)
	}
	if err := g.admit(issued, []byte("sig-b")); err != nil {
		t.Errorf("a DIFFERENT signature issued in the same second was refused as a "+
			"replay: %v — two revokes may legitimately share an issued_at", err)
	}
}
