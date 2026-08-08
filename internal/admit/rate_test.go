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

// fakeClock is a manually-advanced clock so a refill window can be crossed without
// sleeping. It satisfies admit.Clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// TestLimiter_PerCallerBucketIsolatesFloodFromCoTenant is the SEC-55 fairness
// keystone: a single caller flooding the operator ingress exhausts ONLY its own
// bucket; a co-tenant caller keeps its full allowance. One principal cannot consume
// the shared admission capacity by out-requesting everyone else.
func TestLimiter_PerCallerBucketIsolatesFloodFromCoTenant(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	// 3 requests per window per caller.
	lim := admit.NewLimiter(3, time.Second, clk)

	// The flooder burns its 3 tokens, then is throttled.
	for i := 0; i < 3; i++ {
		if !lim.Allow("flooder") {
			t.Fatalf("flooder request %d refused within its allowance", i)
		}
	}
	if lim.Allow("flooder") {
		t.Fatal("flooder's 4th request in the window was allowed; the per-caller cap did not bind")
	}

	// The co-tenant is untouched by the flood: its full allowance remains.
	for i := 0; i < 3; i++ {
		if !lim.Allow("cotenant") {
			t.Fatalf("co-tenant request %d refused — the flooder consumed a shared bucket", i)
		}
	}
}

// TestLimiter_RefillsAfterWindow proves the bucket refills on the next window: a
// throttled caller is allowed again once the clock crosses the window boundary.
func TestLimiter_RefillsAfterWindow(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	lim := admit.NewLimiter(1, time.Second, clk)

	if !lim.Allow("c") {
		t.Fatal("first request refused")
	}
	if lim.Allow("c") {
		t.Fatal("second request in the same window allowed past a cap of 1")
	}
	clk.advance(time.Second) // cross into the next window
	if !lim.Allow("c") {
		t.Fatal("request in a fresh window refused; the bucket did not refill")
	}
}

// TestLimiter_ClockSetbackDoesNotRefillEarly pins the anti-rollback property (the
// same one the quota window relies on): a wall-clock setback within the window must
// NOT hand a throttled caller a fresh bucket. A flooder that could rewind the clock
// would otherwise defeat the cap.
func TestLimiter_ClockSetbackDoesNotRefillEarly(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	lim := admit.NewLimiter(1, time.Minute, clk)

	if !lim.Allow("c") {
		t.Fatal("first request refused")
	}
	// Move backward inside the same nominal window: the bucket label must not become
	// the live one again in a way that resurrects the spent token.
	clk.advance(-30 * time.Second)
	if lim.Allow("c") {
		t.Fatal("a clock setback refilled the bucket early; the cap is rewind-defeatable")
	}
}

// TestLimiter_ZeroCapAllowsAll pins that a non-positive cap disables the limiter
// (fail-open on misconfiguration is the deliberate choice for a rate LIMIT: the
// admission gate is the hard bound, this is the fairness shaper).
func TestLimiter_ZeroCapAllowsAll(t *testing.T) {
	t.Parallel()
	lim := admit.NewLimiter(0, time.Second, newFakeClock())
	for i := 0; i < 100; i++ {
		if !lim.Allow("anyone") {
			t.Fatalf("a zero-cap limiter throttled request %d; it must be disabled", i)
		}
	}
}

// TestNewGate_NegativeSizesClampToEmpty pins the defensive clamp: a negative pool
// size becomes an empty pool of that class rather than a panic (make with a negative
// cap would panic). A gate with a clamped-to-zero general pool refuses a general
// acquire on a done context, and a clamped reserved pool falls back to general.
func TestNewGate_NegativeSizesClampToEmpty(t *testing.T) {
	t.Parallel()
	g := admit.NewGate(-5, -3) // both clamp to 0
	ctx := context.Background()
	// Both pools are empty: a general acquire on a cancelled context refuses without
	// panicking, proving the negative sizes were clamped, not passed to make().
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, ok := g.Acquire(cctx, admit.ClassGeneral); ok {
		t.Fatal("acquired from an empty (negative-clamped) general pool")
	}
}

// TestNewLimiter_NonPositiveWindowClamps pins that a non-positive window does not
// panic (Truncate by a zero duration would); it is clamped to a minimal window and
// the cap still binds within it.
func TestNewLimiter_NonPositiveWindowClamps(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	lim := admit.NewLimiter(1, 0, clk) // window <= 0 clamps to 1ns
	if !lim.Allow("c") {
		t.Fatal("first request refused under a clamped window")
	}
	// Same instant (the fake clock does not advance): still the same window, cap binds.
	if lim.Allow("c") {
		t.Fatal("second request in the same clamped window exceeded a cap of 1")
	}
}

// TestLimiter_ConcurrentAllowIsRaceFree drives many goroutines through one caller's
// bucket; run under -race. The total allowed within a window never exceeds the cap.
func TestLimiter_ConcurrentAllowIsRaceFree(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	const cap = 50
	lim := admit.NewLimiter(cap, time.Second, clk)

	var (
		mu      sync.Mutex
		allowed int
	)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if lim.Allow("k") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed > cap {
		t.Fatalf("allowed %d within the window, exceeding cap %d", allowed, cap)
	}
	if allowed != cap {
		t.Fatalf("allowed %d, want exactly cap %d (all tokens should be handed out)", allowed, cap)
	}
}
