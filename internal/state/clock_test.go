// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fixedStart is an arbitrary fixed instant tests anchor on for reproducibility.
var fixedStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

func TestSystemClock_SatisfiesInterface(t *testing.T) {
	t.Parallel()
	var _ state.Clock = state.SystemClock()
}

func TestSystemClock_NowAdvancesAndSinceIsNonNegative(t *testing.T) {
	t.Parallel()
	c := state.SystemClock()

	before := c.Now()
	mark := c.Now()
	after := c.Now()

	if before.After(mark) || mark.After(after) {
		t.Fatalf("Now must be monotonically non-decreasing: before=%v mark=%v after=%v",
			before, mark, after)
	}

	// Since against a fresh mark is elapsed wall/monotonic time: never negative,
	// and bounded above by a generous slack for a few back-to-back reads.
	elapsed := c.Since(mark)
	if elapsed < 0 {
		t.Fatalf("Since against a just-taken mark must be non-negative, got %v", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("Since against a just-taken mark unexpectedly large: %v", elapsed)
	}
}

func TestSystemClock_SinceMeasuresRealElapsed(t *testing.T) {
	t.Parallel()
	c := state.SystemClock()

	mark := c.Now()
	time.Sleep(5 * time.Millisecond)
	elapsed := c.Since(mark)

	if elapsed < 5*time.Millisecond {
		t.Fatalf("Since should reflect at least the slept duration, got %v", elapsed)
	}
}

func TestFakeClock_SatisfiesInterface(t *testing.T) {
	t.Parallel()
	var _ state.Clock = state.NewFakeClock(fixedStart)
}

func TestFakeClock_NowStartsAtConstructorInstant(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)

	if got := c.Now(); !got.Equal(fixedStart) {
		t.Fatalf("Now should start at the constructor instant: want %v got %v", fixedStart, got)
	}
}

func TestFakeClock_SinceAgainstStartMarkIsZeroBeforeAdvance(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)
	mark := c.Now()

	if got := c.Since(mark); got != 0 {
		t.Fatalf("Since against the start mark before any Advance should be zero, got %v", got)
	}
}

func TestFakeClock_AdvanceMovesBothNowAndSince(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)
	mark := c.Now()

	c.Advance(90 * time.Second)

	wantNow := fixedStart.Add(90 * time.Second)
	if got := c.Now(); !got.Equal(wantNow) {
		t.Fatalf("Advance should move Now forward: want %v got %v", wantNow, got)
	}
	if got := c.Since(mark); got != 90*time.Second {
		t.Fatalf("Advance should move Since forward: want %v got %v", 90*time.Second, got)
	}
}

func TestFakeClock_AdvanceAccumulates(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)
	mark := c.Now()

	c.Advance(30 * time.Second)
	c.Advance(30 * time.Second)

	if got := c.Since(mark); got != time.Minute {
		t.Fatalf("successive Advance calls should accumulate: want %v got %v", time.Minute, got)
	}
}

// TestFakeClock_WallSetbackDoesNotMoveSince is the load-bearing case: moving the
// wall clock backward changes Now but must leave Since measuring the unmoved
// monotonic base, so a setback extends no window (requirement 6, NFR-SEC-48).
func TestFakeClock_WallSetbackDoesNotMoveSince(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)
	mark := c.Now()

	// Real time passes: both readings move forward.
	c.Advance(time.Hour)
	if got := c.Since(mark); got != time.Hour {
		t.Fatalf("precondition: Since should be one hour after Advance, got %v", got)
	}

	// An operator/NTP setback drags the wall clock far into the past.
	setback := fixedStart.Add(-24 * time.Hour)
	c.SetWallClock(setback)

	if got := c.Now(); !got.Equal(setback) {
		t.Fatalf("SetWallClock should move Now backward: want %v got %v", setback, got)
	}
	// The monotonic-based Since must be unchanged by the setback.
	if got := c.Since(mark); got != time.Hour {
		t.Fatalf("wall setback must not change Since: want %v got %v", time.Hour, got)
	}
}

// TestFakeClock_AdvanceAfterSetbackStillMovesSince proves the monotonic base is
// independent of the wall reading: after a wall setback, Advance still moves
// Since forward from where it was, and Now resumes from the (set-back) wall
// reading plus the advance.
func TestFakeClock_AdvanceAfterSetbackStillMovesSince(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)
	mark := c.Now()

	c.Advance(time.Hour)
	c.SetWallClock(fixedStart.Add(-24 * time.Hour))
	c.Advance(time.Minute)

	if got := c.Since(mark); got != time.Hour+time.Minute {
		t.Fatalf("Advance after a setback must keep moving Since: want %v got %v",
			time.Hour+time.Minute, got)
	}
	wantNow := fixedStart.Add(-24 * time.Hour).Add(time.Minute)
	if got := c.Now(); !got.Equal(wantNow) {
		t.Fatalf("Now after setback+advance: want %v got %v", wantNow, got)
	}
}

func TestFakeClock_SinceWithMarkInFutureOfBaseIsNegative(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)

	// A mark ahead of the current monotonic base yields a negative duration,
	// matching time.Since semantics for an out-of-order mark.
	future := fixedStart.Add(time.Minute)
	if got := c.Since(future); got != -time.Minute {
		t.Fatalf("Since against a future mark should be negative: want %v got %v",
			-time.Minute, got)
	}
}

// TestFakeClock_ConcurrentAccess exercises the mutex under the race detector:
// concurrent Advance, SetWallClock, Now, and Since calls must not data-race.
func TestFakeClock_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	c := state.NewFakeClock(fixedStart)
	mark := c.Now()

	const goroutines = 8
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				c.Advance(time.Millisecond)
				_ = c.Now()
				_ = c.Since(mark)
				c.SetWallClock(fixedStart)
			}
		}()
	}
	wg.Wait()

	// Every goroutine advanced the base once per iteration; the total is exact
	// because Advance is serialized by the mutex.
	wantSince := time.Duration(goroutines*iterations) * time.Millisecond
	if got := c.Since(mark); got != wantSince {
		t.Fatalf("serialized Advance total mismatch: want %v got %v", wantSince, got)
	}
}
