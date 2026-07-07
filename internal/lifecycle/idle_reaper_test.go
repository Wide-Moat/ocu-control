// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

const testIdleTTL = 15 * time.Minute

// TestReapIdle_AbandonedSessionReclaimed is the Finding #3 keystone. An ACTIVE
// session whose client vanished (crash, network drop, OOM on the caller side)
// without calling destroy holds its concurrency slot forever: boot-reconcile only
// runs at restart, the kill-switch only on an operator action, and neither ticks. A
// session idle past idleTTL — no exec or control activity — must be reclaimed by the
// runtime reaper so an abandoned session cannot wedge the tier cap (a fail-open DoS).
//
// The idle window is measured entirely through the injected Clock (two in-process
// readings: the last-activity stamp vs Clock.Now() at reap), never a stored-timestamp
// subtraction, so a wall-clock setback cannot move the reclaim (NFR-SEC-48). This
// advances the FakeClock past idleTTL with no activity and asserts the slot returns
// and a reclaim audit record is written. Skip the reap and the slot stays charged —
// this reds.
func TestReapIdle_AbandonedSessionReclaimed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.mgr.Create(ctx, input("abandoned"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 1 {
		t.Fatalf("post-create concurrency = %d, want 1", got)
	}

	// The client vanished: no exec, no destroy. Time passes beyond idleTTL.
	h.clk.Advance(testIdleTTL + time.Minute)

	reaped, err := h.mgr.ReapIdle(ctx, testIdleTTL)
	if err != nil {
		t.Fatalf("ReapIdle: %v", err)
	}
	if reaped != 1 {
		t.Fatalf("ReapIdle reaped %d sessions, want 1 (the abandoned one)", reaped)
	}

	// The abandoned row is reclaimed to the tombstone and its slot returned.
	row, err := h.store.LookupSession(ctx, created.Key)
	if err != nil {
		t.Fatalf("lookup after reap: %v", err)
	}
	if row.State != state.StateReleased {
		t.Fatalf("abandoned session must be reclaimed to RELEASED, got %v", row.State)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 0 {
		t.Fatalf("post-reap concurrency = %d, want 0 (slot returned)", got)
	}
	// The abandoned CONTAINER is gone from the substrate, not just the row. A reaper
	// that only returns the slot without tearing down the guest trades a slot leak for
	// an orphan-container leak: the in-guest agent service is a long-lived UDS server, so
	// exec-exit never kills it — reapOne MUST force-kill the substrate. The provider
	// holds nothing for the reaped session after the reap.
	if got := h.provider.liveCount(); got != 0 {
		t.Fatalf("post-reap provider live containers = %d, want 0 (the abandoned guest must be force-killed, not orphaned)", got)
	}
	// The reclaim is recorded: a reconcile-reclaim-class audit event names the idle-reap
	// cause so the operator trail distinguishes it from a normal destroy.
	var reaps int
	for _, r := range h.audit.Records() {
		if r.Action == audit.ActionReconcileReclaim {
			reaps++
		}
	}
	if reaps != 1 {
		t.Fatalf("idle reap emitted %d reconcile-reclaim records, want 1", reaps)
	}
}

// TestReapIdle_SecondReapIsIdempotent is the guard on re-running the reaper against a
// session a prior tick already reclaimed. Once reaped the row is RELEASED, so it is no
// longer an ACTIVE reap candidate and the second tick selects it not at all — reaped=0,
// the slot stays at zero (no double-credit), and no second reconcile-reclaim record is
// written. This locks the invariant that overlapping or retried ticks converge rather
// than compounding: the reaper's per-row work (force-kill, release, refund) is each
// idempotent, and the row-state skip means an already-reaped session is never revisited.
func TestReapIdle_SecondReapIsIdempotent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.mgr.Create(ctx, input("abandoned-twice")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	h.clk.Advance(testIdleTTL + time.Minute)

	first, err := h.mgr.ReapIdle(ctx, testIdleTTL)
	if err != nil {
		t.Fatalf("first ReapIdle: %v", err)
	}
	if first != 1 {
		t.Fatalf("first ReapIdle reaped %d, want 1", first)
	}

	// A second tick over the same now-RELEASED session must reclaim nothing.
	second, err := h.mgr.ReapIdle(ctx, testIdleTTL)
	if err != nil {
		t.Fatalf("second ReapIdle: %v", err)
	}
	if second != 0 {
		t.Fatalf("second ReapIdle reaped %d, want 0 (the session was already reclaimed)", second)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 0 {
		t.Fatalf("post-second-reap concurrency = %d, want 0 (no double-credit)", got)
	}
	var reaps int
	for _, r := range h.audit.Records() {
		if r.Action == audit.ActionReconcileReclaim {
			reaps++
		}
	}
	if reaps != 1 {
		t.Fatalf("total reconcile-reclaim records after two ticks = %d, want 1 (the second tick reclaims nothing)", reaps)
	}
}

// TestReapIdle_ActiveSessionUntouched is the paired guard: a session with RECENT
// activity (an exec within idleTTL) must NOT be reaped even though wall time since
// Commit exceeds idleTTL — the reaper measures idle from the LAST activity, not from
// creation, so a long-running legitimate session that keeps exec'ing is never killed.
func TestReapIdle_ActiveSessionUntouched(t *testing.T) {
	t.Parallel()
	h := newHarnessWithExec(t, &recordingExecDriver{})
	ctx := context.Background()

	created, err := h.mgr.Create(ctx, input("busy"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Long-running session: well past idleTTL since Commit, but it keeps working.
	h.clk.Advance(testIdleTTL * 2)
	if _, err := h.mgr.Exec(ctx, testCaller, "busy", lifecycle.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	// Only a little time passes AFTER the exec — well within idleTTL.
	h.clk.Advance(time.Minute)

	reaped, err := h.mgr.ReapIdle(ctx, testIdleTTL)
	if err != nil {
		t.Fatalf("ReapIdle: %v", err)
	}
	if reaped != 0 {
		t.Fatalf("ReapIdle reaped %d sessions, want 0 (recent exec keeps it alive)", reaped)
	}
	row, err := h.store.LookupSession(ctx, created.Key)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("busy session must stay ACTIVE, got %v", row.State)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 1 {
		t.Fatalf("busy session must keep its slot, concurrency = %d, want 1", got)
	}
}
