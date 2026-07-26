// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// The idle-session reaper tick. The lifecycle Manager owns the reap logic (enumerate
// idle ACTIVE sessions, force-kill and reclaim each); this file owns only the daemon
// serve-loop that drives it periodically and its shelf-split gate. The tick runs iff
// the resolved idle window is positive — an off window (the minimal shelf, or an unset
// solo deployment) starts NO goroutine, so "off" costs nothing at runtime.

package main

import (
	"context"
	"time"
)

// idleReaper is the narrow seam the serve loop drives: one periodic reclaim pass over
// idle ACTIVE sessions. It is satisfied by *lifecycle.Manager (its ReapIdle method) so
// this file depends on the verb, not the whole Manager surface, and a test can drive
// the loop with a counting fake.
type idleReaper interface {
	ReapIdle(ctx context.Context, idleTTL time.Duration) (int, error)
}

// startIdleReaper launches the idle-session reaper goroutine when the resolved idle
// window is positive, and returns whether it launched anything. A zero (or negative)
// window means the reaper is OFF: no goroutine is started, so an off deployment burns
// no ticker and no scheduler slot — "off" is structural, not a no-op tick. The caller
// resolves the window through resolveIdleTTL (the NFR-SEC-40 shelf split) before
// calling this, so on the minimal shelf an unset window is 0 (off) and on the full
// shelf it is the ≤15 min ceiling (on).
//
// When started, the goroutine ticks every idleTTL/2 — twice per window, so an idle
// session is reclaimed within at most 1.5 windows of going idle — calling ReapIdle
// each tick and returning when ctx is cancelled (the daemon shutdown signal). A
// per-tick ReapIdle error is intentionally not fatal to the loop: the reaper is a
// best-effort background reclaim, and a transient enumerate/teardown failure must not
// tear down the daemon; the next tick retries. The tick interval never drops below a
// small floor so a very short (test-scale) window cannot spin.
// observe, when non-nil, receives each tick's outcome (reaped count, error). It exists
// because the loop is best-effort: a failing tick must not kill the daemon, but the
// per-reclaim durable audit only covers reclaims that HAPPEN -- ReapIdle enumerates
// first (manager.go), and an enumerate failure returns (0, err) with ZERO audit records
// and ZERO metrics, so a persistently-broken reaper is otherwise indistinguishable from
// "nothing is idle" until idle slots pile into the tier cap. observe surfaces the count
// (throughput) and the error (stuck-reaper alarm) to the daemon's Collector; a nil
// observe is deliberate silence (the same off-cost as before this param existed).
func startIdleReaper(ctx context.Context, r idleReaper, idleTTL time.Duration, observe func(reaped int, err error)) bool {
	if idleTTL <= 0 {
		return false
	}
	interval := idleTTL / 2
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// A tick error is non-fatal: one failed pass never kills the loop; the next
				// tick retries. The outcome is reported to observe (not swallowed) so a
				// persistently-failing reaper is alarmable instead of silent.
				n, err := r.ReapIdle(ctx, idleTTL)
				if observe != nil {
					observe(n, err)
				}
			}
		}
	}()
	return true
}
