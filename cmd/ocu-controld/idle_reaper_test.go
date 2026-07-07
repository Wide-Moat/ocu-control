// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingReaper is a fake idleReaper that records how many times ReapIdle was called
// and the idleTTL each tick passed, so a test can assert whether the reaper loop was
// started at all and that it forwards the resolved window.
type countingReaper struct {
	calls   atomic.Int64
	mu      sync.Mutex
	lastTTL time.Duration
}

func (r *countingReaper) ReapIdle(_ context.Context, idleTTL time.Duration) (int, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.lastTTL = idleTTL
	r.mu.Unlock()
	return 0, nil
}

func (r *countingReaper) ttl() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastTTL
}

// Test_startIdleReaper_NotStartedWhenOff proves the reaper goroutine is STRUCTURALLY
// not started when the resolved window is zero (the minimal-shelf off case). This is
// the "off means the loop does not run" guard: startIdleReaper reports it launched
// nothing, and the fake reaper is never called even after time passes. A goroutine
// that started and merely no-op'd each tick would still burn a ticker and a scheduler
// slot; "off" must mean no goroutine at all.
func Test_startIdleReaper_NotStartedWhenOff(t *testing.T) {
	t.Parallel()
	r := &countingReaper{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := startIdleReaper(ctx, r, 0)
	if started {
		t.Fatal("startIdleReaper reported started=true for a zero window; the reaper must not run when off")
	}
	// Even after real time passes, the reaper is never invoked.
	time.Sleep(20 * time.Millisecond)
	if got := r.calls.Load(); got != 0 {
		t.Fatalf("reaper called %d times with the window off, want 0 (no goroutine started)", got)
	}
}

// Test_startIdleReaper_TicksWhenOn proves that with a positive resolved window the
// reaper goroutine IS started and ticks, forwarding the resolved window to ReapIdle,
// and that a context cancel stops it. The tick interval is half the window, so a short
// window ticks quickly enough to observe within the test.
func Test_startIdleReaper_TicksWhenOn(t *testing.T) {
	t.Parallel()
	r := &countingReaper{}
	ctx, cancel := context.WithCancel(context.Background())

	window := 20 * time.Millisecond
	started := startIdleReaper(ctx, r, window)
	if !started {
		t.Fatal("startIdleReaper reported started=false for a positive window; the reaper must run when on")
	}

	// Wait for at least one tick (interval is window/2 = 10ms).
	deadline := time.Now().Add(2 * time.Second)
	for r.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("reaper never ticked within 2s for a 20ms window")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := r.ttl(); got != window {
		t.Fatalf("reaper tick forwarded idleTTL = %v, want the resolved window %v", got, window)
	}

	// Cancel stops the loop: record the count, wait, and assert it stopped advancing.
	cancel()
	time.Sleep(30 * time.Millisecond)
	stopped := r.calls.Load()
	time.Sleep(40 * time.Millisecond)
	if got := r.calls.Load(); got != stopped {
		t.Fatalf("reaper kept ticking after ctx cancel: %d then %d — it must stop on shutdown", stopped, got)
	}
}

// Test_resolveIdleTTL_ShelfSplit is the idle-reaper flag-resolution keystone. The
// canon (NFR-SEC-40) mandates a shelf split: the idle timeout is OFF-legal on the
// minimal/solo shelf (no durable state) but is ON, bounded by a ≤15 min ceiling, on
// the full shelf. So -session-idle-ttl does NOT resolve to "0 = off by default"
// uniformly — its resolution depends on the shelf, which the daemon reads from
// -state-dsn (empty = in-memory minimal shelf, set = Postgres full shelf).
//
// The table pins every arm; the two non-vacuous arms that make the split real are:
//   - full-shelf UNSET resolves to the ceiling (unset ≠ off — the reaper RUNS at
//     ≤15 min, it does not silently stay off), and
//   - full-shelf ABOVE the ceiling is REFUSED, not silently clamped. A silent clamp
//     is a config-integrity lie: an operator who sets 30 min and is quietly given 15
//     believes a wider window is in force than actually is. Refuse-not-clamp makes
//     the misconfiguration loud at boot.
func Test_resolveIdleTTL_ShelfSplit(t *testing.T) {
	t.Parallel()

	const dsn = "postgres://localhost/ocu" // any non-empty DSN selects the full shelf

	cases := []struct {
		name     string
		stateDSN string
		ttl      time.Duration
		want     time.Duration
		wantErr  bool
	}{
		// Minimal shelf (empty DSN): OFF is legal. Unset stays off; a positive value is
		// an explicit solo-shelf opt-in and is honored; a negative value is nonsense.
		{name: "minimal_unset_is_off", stateDSN: "", ttl: 0, want: 0},
		{name: "minimal_positive_opt_in_honored", stateDSN: "", ttl: 5 * time.Minute, want: 5 * time.Minute},
		{name: "minimal_negative_refused", stateDSN: "", ttl: -time.Second, wantErr: true},

		// Full shelf (set DSN): ON is mandatory (SEC-40). Unset resolves UP to the
		// ceiling (the reaper runs), a value at-or-below the ceiling is honored (tunable
		// DOWN), a value ABOVE the ceiling is REFUSED (not clamped), negative refused.
		{name: "full_unset_resolves_to_ceiling", stateDSN: dsn, ttl: 0, want: sessionIdleCeiling},
		{name: "full_below_ceiling_honored", stateDSN: dsn, ttl: 10 * time.Minute, want: 10 * time.Minute},
		{name: "full_at_ceiling_honored", stateDSN: dsn, ttl: sessionIdleCeiling, want: sessionIdleCeiling},
		{name: "full_above_ceiling_refused", stateDSN: dsn, ttl: 30 * time.Minute, wantErr: true},
		{name: "full_negative_refused", stateDSN: dsn, ttl: -time.Second, wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveIdleTTL(config{stateDSN: tc.stateDSN, sessionIdleTTL: tc.ttl})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveIdleTTL(dsn=%q, ttl=%v) = %v, nil; want a refusal", tc.stateDSN, tc.ttl, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveIdleTTL(dsn=%q, ttl=%v): unexpected error %v", tc.stateDSN, tc.ttl, err)
			}
			if got != tc.want {
				t.Fatalf("resolveIdleTTL(dsn=%q, ttl=%v) = %v, want %v", tc.stateDSN, tc.ttl, got, tc.want)
			}
		})
	}
}

// Test_resolveIdleTTL_AboveCeilingIsTypedRefusal proves the above-ceiling refusal
// carries the typed errIdleTTLAboveCeiling sentinel (not a bare string), so a caller
// can attribute the boot abort to exactly this misconfiguration and the refusal is
// distinguishable from an unrelated flag error.
func Test_resolveIdleTTL_AboveCeilingIsTypedRefusal(t *testing.T) {
	t.Parallel()
	_, err := resolveIdleTTL(config{stateDSN: "postgres://localhost/ocu", sessionIdleTTL: time.Hour})
	if !errors.Is(err, errIdleTTLAboveCeiling) {
		t.Fatalf("resolveIdleTTL above ceiling error = %v, want errIdleTTLAboveCeiling", err)
	}
}

// Test_parse_SessionIdleTTL_Unset proves -session-idle-ttl defaults to zero (unset)
// so an invocation without it parses cleanly; the shelf-split resolution above turns
// that zero into off (minimal) or the ceiling (full), never here.
func Test_parse_SessionIdleTTL_Unset(t *testing.T) {
	t.Parallel()
	args := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
	}
	cfg, _, err := parse(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.sessionIdleTTL != 0 {
		t.Fatalf("sessionIdleTTL = %v, want 0 (unset)", cfg.sessionIdleTTL)
	}
}

// Test_parse_SessionIdleTTL_Set proves -session-idle-ttl is parsed as a duration.
func Test_parse_SessionIdleTTL_Set(t *testing.T) {
	t.Parallel()
	args := []string{
		"-operator-listen", "unix:///tmp/test.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/jwt.key",
		"-audit-sink", "/tmp/audit.jsonl",
		"-session-idle-ttl", "10m",
	}
	cfg, _, err := parse(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.sessionIdleTTL != 10*time.Minute {
		t.Fatalf("sessionIdleTTL = %v, want 10m", cfg.sessionIdleTTL)
	}
}
