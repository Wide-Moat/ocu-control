// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package admit

import (
	"sync"
	"time"
)

// Clock is the time source the Limiter reads to place a request in its window. The
// operator adapter injects the real clock; a test injects a fake so a window can be
// crossed without sleeping. It is the same minimal seam the quota gate uses.
type Clock interface {
	Now() time.Time
}

// Limiter is a per-caller windowed request cap: the SEC-55 fairness half. Each
// distinct caller key gets `cap` requests per `window`; a caller that exceeds its
// cap within the window is throttled while co-tenant callers keep their full
// allowance, so one principal flooding the operator ingress cannot consume the
// shared admission capacity. The window is a fixed tumbling window keyed by a label
// derived from the clock.
//
// A wall-clock setback cannot refill a spent bucket early: the limiter tracks a
// per-caller monotonic window floor and treats any label at or before the floor as
// the floor's live bucket rather than a fresh earlier one, so rewinding the clock
// (even across a window boundary) reuses the same count instead of resetting it.
// Only a label strictly AFTER the floor advances to a fresh bucket. A flooder that
// rewinds the clock does not defeat the cap.
//
// A non-positive cap disables the limiter (Allow always true): the admission Gate
// is the hard concurrency bound, and this shaper fails open on misconfiguration so
// a zero-cap deployment is not accidentally locked out.
type Limiter struct {
	cap    int
	window time.Duration
	clk    Clock

	mu    sync.Mutex
	state map[string]*callerState // caller -> its live window floor + count
}

// callerState is one caller's live window: the monotonic floor (the window-start
// instant it advanced to) and how many requests it has spent in that window. A
// setback to an earlier window reuses this same state (no early refill); a window
// strictly after `floor` resets count to 0 and raises the floor.
type callerState struct {
	floor time.Time
	count int
}

// NewLimiter builds a per-caller limiter of `cap` requests per `window`. A
// non-positive cap disables it. A non-positive window is treated as the smallest
// meaningful window (1ns) so the label math never divides by zero; a caller passing
// zero window with a positive cap gets an effectively per-instant cap, which is a
// misconfiguration the caller is responsible for, not a panic.
func NewLimiter(cap int, window time.Duration, clk Clock) *Limiter {
	if window <= 0 {
		window = time.Nanosecond
	}
	return &Limiter{
		cap:    cap,
		window: window,
		clk:    clk,
		state:  make(map[string]*callerState),
	}
}

// Allow records one request for caller and reports whether it is within the
// caller's per-window cap. It is safe for concurrent use. A disabled limiter (cap
// <= 0) always returns true and records nothing.
func (l *Limiter) Allow(caller string) bool {
	if l.cap <= 0 {
		return true
	}
	// The window-start instant this request falls in. Truncate is UTC-stable for a
	// fixed duration, so the boundary does not shift with timezone.
	winStart := l.clk.Now().Truncate(l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.state[caller]
	switch {
	case st == nil:
		// First request from this caller: open its window at winStart.
		st = &callerState{floor: winStart, count: 0}
		l.state[caller] = st
	case winStart.After(st.floor):
		// A strictly later window: refill (raise the floor, reset the count). This is
		// the ONLY path that resets the count, so a setback cannot trigger it.
		st.floor = winStart
		st.count = 0
	default:
		// winStart == floor (same live window) OR winStart < floor (a clock setback):
		// both reuse the live window's count, so a rewind never refills early.
	}

	if st.count >= l.cap {
		return false
	}
	st.count++
	return true
}
