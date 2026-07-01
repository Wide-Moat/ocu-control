// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state

import (
	"sync"
	"time"
)

// systemClock is the production Clock seam. Now reads the OS wall clock, which
// time.Now stamps with a monotonic reading; Since defers to time.Since, which
// subtracts that monotonic reading and is therefore immune to a wall-clock
// setback between the mark and the measurement. The control plane uses a single
// shared instance: it carries no state and is safe for concurrent use.
type systemClock struct{}

// SystemClock returns the production monotonic Clock backed by the OS clock.
func SystemClock() Clock {
	return systemClock{}
}

// Now returns the current instant. The returned time.Time carries a monotonic
// reading, so a later Since against it measures elapsed monotonic time.
func (systemClock) Now() time.Time {
	return time.Now()
}

// Since returns the monotonic elapsed time from mark. Because mark was produced
// by Now (which embeds a monotonic reading), time.Since subtracts that reading
// rather than the wall clock, so a wall-clock setback cannot inflate or shrink
// the result. A mark loaded back from durable storage has no monotonic reading
// and must never be passed here.
func (systemClock) Since(mark time.Time) time.Duration {
	return time.Since(mark)
}

// FakeClock is a deterministic, advanceable Clock for conformance and property
// tests. It splits the two readings the production clock fuses into one:
//
//   - a wall reading that Now returns and that SetWallClock may move in either
//     direction, modelling an operator or NTP setback; and
//   - a monotonic base that only Advance moves, and only ever forward, against
//     which Since measures elapsed time.
//
// This split lets a test prove the security invariant the Clock seam exists for:
// moving the wall clock backward with SetWallClock changes what Now reports but
// leaves Since untouched, so no TTL or revocation window is extended by a
// setback (requirement 6, NFR-SEC-48). Advance moves both readings forward
// together, the way real time passes. FakeClock is safe for concurrent use.
type FakeClock struct {
	mu sync.Mutex
	// wall is what Now reports; SetWallClock and Advance both move it.
	wall time.Time
	// mono is the monotonic base Since measures against; only Advance moves it,
	// and only forward. It carries no wall-clock semantics and is never returned.
	mono time.Time
}

// NewFakeClock returns a FakeClock whose wall reading and monotonic base both
// start at start. Tests pass a fixed instant so runs are reproducible.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{
		wall: start,
		mono: start,
	}
}

// Now returns the current settable wall instant. It may have been moved
// backward by SetWallClock; that is the modelled setback and does not affect
// Since.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

// Since returns the elapsed time from mark measured against the monotonic base.
// Only Advance moves that base, so a wall-clock setback via SetWallClock never
// changes this result. mark is interpreted on the same monotonic timeline a
// prior Now produced; passing a mark from the future of the base yields a
// negative duration exactly as time.Since would.
func (c *FakeClock) Since(mark time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono.Sub(mark)
}

// Advance moves both the wall reading and the monotonic base forward by d, the
// way real time passes. A non-positive d is accepted and applied as given, so a
// test may model a stall (zero) without a special case; use SetWallClock to
// move only the wall reading backward.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.mono = c.mono.Add(d)
}

// SetWallClock sets what Now returns, in either direction, without touching the
// monotonic base. It models a wall-clock setback (or jump): Now reflects t, but
// Since keeps measuring against the unmoved base, proving a setback extends no
// window.
func (c *FakeClock) SetWallClock(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = t
}
