// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package quota_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// gateStart is the fixed instant the quota tests anchor their FakeClock on, so
// the per-minute window label is reproducible across runs.
var gateStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// readOnlyForbiddenStore wraps an in-memory Store and FAILS the test if ReadQuota
// is consulted on the gate path: a Read-then-Charge is the forbidden TOCTOU, so
// the gate must drive every decision through the atomic Charge alone.
type readOnlyForbiddenStore struct {
	state.Store
	t *testing.T
}

func (s readOnlyForbiddenStore) ReadQuota(ctx context.Context, key state.QuotaKey) (int64, error) {
	s.t.Fatalf("gate consulted ReadQuota (forbidden Read-then-Charge / TOCTOU) for dim=%d", key.Dim)
	return 0, nil
}

// newGate builds a Gate over a fresh in-memory Store wrapped to forbid ReadQuota,
// returning both so a test can inspect counters via the underlying Store.
func newGate(t *testing.T, clk state.Clock, limits quota.Limits) (*quota.Gate, state.Store) {
	t.Helper()
	inner := state.NewInMemory(clk)
	guarded := readOnlyForbiddenStore{Store: inner, t: t}
	return quota.NewGate(guarded, clk, limits), inner
}

// readConcurrent reads the per-tenant concurrent-session level counter directly
// from the underlying Store for an assertion (the test, not the gate, may read).
func readConcurrent(t *testing.T, store state.Store, id state.Identity) int64 {
	t.Helper()
	v, err := store.ReadQuota(context.Background(), state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id})
	if err != nil {
		t.Fatalf("ReadQuota(concurrent): %v", err)
	}
	return v
}

// readCreateRate reads the per-caller create-rate windowed counter for the
// current minute window.
func readCreateRate(t *testing.T, store state.Store, clk state.Clock, id state.Identity) int64 {
	t.Helper()
	window := clk.Now().UTC().Truncate(time.Minute).Format("2006-01-02T15:04Z")
	v, err := store.ReadQuota(context.Background(), state.QuotaKey{Dim: state.DimCallerCreateRate, Identity: id, Window: window})
	if err != nil {
		t.Fatalf("ReadQuota(create-rate): %v", err)
	}
	return v
}

// TestChargeCreateIssuesBothCharges proves a successful ChargeCreate increments
// both the create-rate and the concurrent counters by one and returns a Receipt.
func TestChargeCreateIssuesBothCharges(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: unexpected error %v", err)
	}
	if rcpt == nil {
		t.Fatalf("ChargeCreate: nil receipt on success")
	}
	if got := readCreateRate(t, store, clk, id); got != 1 {
		t.Fatalf("create-rate counter = %d, want 1", got)
	}
	if got := readConcurrent(t, store, id); got != 1 {
		t.Fatalf("concurrent counter = %d, want 1", got)
	}
}

// TestChargeCreateRefusedOnCreateRateLeavesNothing proves a first-charge refusal
// (create-rate at limit) moves no counter and returns ErrQuotaExceeded with no
// receipt.
func TestChargeCreateRefusedOnCreateRateLeavesNothing(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 1, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	if _, err := g.ChargeCreate(context.Background(), id); err != nil {
		t.Fatalf("first ChargeCreate: unexpected error %v", err)
	}
	// Second create exceeds the per-caller create-rate of 1.
	rcpt, err := g.ChargeCreate(context.Background(), id)
	if !errors.Is(err, state.ErrQuotaExceeded) {
		t.Fatalf("second ChargeCreate: error %v, want ErrQuotaExceeded", err)
	}
	if rcpt != nil {
		t.Fatalf("second ChargeCreate: non-nil receipt on refusal")
	}
	// The refused create touched neither counter beyond the first success.
	if got := readCreateRate(t, store, clk, id); got != 1 {
		t.Fatalf("create-rate counter = %d after refusal, want 1 (unchanged)", got)
	}
	if got := readConcurrent(t, store, id); got != 1 {
		t.Fatalf("concurrent counter = %d after refusal, want 1 (unchanged)", got)
	}
}

// TestChargeCreateRefundsFirstWhenConcurrentExceeded is the refund-on-partial
// invariant: when the second (concurrent) charge is refused, the first
// (create-rate) charge is refunded before return, so zero net counter moved.
func TestChargeCreateRefundsFirstWhenConcurrentExceeded(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	// Concurrent limit 1: the first create fills it; the second must refuse on
	// concurrent AND refund its already-applied create-rate charge.
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 100, ConcurrentSessionsPerTenant: 1})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	if _, err := g.ChargeCreate(context.Background(), id); err != nil {
		t.Fatalf("first ChargeCreate: unexpected error %v", err)
	}
	rateAfterFirst := readCreateRate(t, store, clk, id)

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if !errors.Is(err, state.ErrQuotaExceeded) {
		t.Fatalf("second ChargeCreate: error %v, want ErrQuotaExceeded", err)
	}
	if rcpt != nil {
		t.Fatalf("second ChargeCreate: non-nil receipt on refusal")
	}
	// The create-rate counter is back to its pre-second value: the partial charge
	// was refunded, so zero net counter movement.
	if got := readCreateRate(t, store, clk, id); got != rateAfterFirst {
		t.Fatalf("create-rate counter = %d after refunded refusal, want %d (refunded)", got, rateAfterFirst)
	}
	if got := readConcurrent(t, store, id); got != 1 {
		t.Fatalf("concurrent counter = %d after refusal, want 1 (the first create only)", got)
	}
}

// TestReceiptApplyRefundsBothCells proves the unwind compensator refunds exactly
// the two cells a successful ChargeCreate applied, and is idempotent on re-run.
func TestReceiptApplyRefundsBothCells(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	if err := rcpt.Apply(context.Background()); err != nil {
		t.Fatalf("Receipt.Apply: %v", err)
	}
	if got := readCreateRate(t, store, clk, id); got != 0 {
		t.Fatalf("create-rate counter = %d after Apply, want 0", got)
	}
	if got := readConcurrent(t, store, id); got != 0 {
		t.Fatalf("concurrent counter = %d after Apply, want 0", got)
	}
	// Idempotent: a second Apply is a no-op (the Store saturates a negative delta
	// at zero anyway, but the Receipt also clears its cells).
	if err := rcpt.Apply(context.Background()); err != nil {
		t.Fatalf("second Receipt.Apply: %v", err)
	}
	if got := readConcurrent(t, store, id); got != 0 {
		t.Fatalf("concurrent counter = %d after second Apply, want 0", got)
	}
}

// TestRefundConcurrentDecrementsAndSaturates proves the shared concurrent-slot
// decrement the lifecycle destroy path and the boot reconciler both call: it returns
// one level slot, and a second call on an already-zero counter saturates at zero
// rather than going negative.
func TestRefundConcurrentDecrementsAndSaturates(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	if _, err := g.ChargeCreate(context.Background(), id); err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	if got := readConcurrent(t, store, id); got != 1 {
		t.Fatalf("concurrent after charge = %d, want 1", got)
	}
	if err := g.RefundConcurrent(context.Background(), id); err != nil {
		t.Fatalf("RefundConcurrent: %v", err)
	}
	if got := readConcurrent(t, store, id); got != 0 {
		t.Fatalf("concurrent after refund = %d, want 0", got)
	}
	// A second refund on an already-zero counter must saturate at zero, never go
	// negative (a double decrement from destroy + reconcile must not leak downward).
	if err := g.RefundConcurrent(context.Background(), id); err != nil {
		t.Fatalf("second RefundConcurrent: %v", err)
	}
	if got := readConcurrent(t, store, id); got != 0 {
		t.Fatalf("concurrent after second refund = %d, want 0 (saturated)", got)
	}
}

// TestReceiptApplyUnderCancelledContext proves the refund still runs when the
// caller's context is already cancelled (WithoutCancel detaches the refund), so a
// client disconnect mid-create cannot strand a charged counter.
func TestReceiptApplyUnderCancelledContext(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Apply

	if err := rcpt.Apply(ctx); err != nil {
		t.Fatalf("Receipt.Apply under cancelled ctx: %v", err)
	}
	if got := readConcurrent(t, store, id); got != 0 {
		t.Fatalf("concurrent counter = %d after Apply under cancelled ctx, want 0", got)
	}
}

// TestNilReceiptApply proves Apply tolerates a nil Receipt (the refused-create
// path returns nil), so the unwind never panics.
func TestNilReceiptApply(t *testing.T) {
	t.Parallel()
	var r *quota.Receipt
	if err := r.Apply(context.Background()); err != nil {
		t.Fatalf("nil Receipt.Apply: %v", err)
	}
}

// TestWallClockSetbackYieldsDifferentBucket is the must-fix window invariant: a
// wall-clock setback moves the create-rate to an EARLIER bucket label rather than
// re-entering the live bucket, so a flood cannot exceed the per-window limit
// within one true window. We fill the limit in the live window, then set the wall
// clock back and observe the create lands in a different (empty) bucket — it does
// not get refused as if the live bucket were re-entered, and the live bucket's
// count is unchanged.
func TestWallClockSetbackYieldsDifferentBucket(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, store := newGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 1, ConcurrentSessionsPerTenant: 100})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	// Fill the create-rate limit (1) in the live window.
	if _, err := g.ChargeCreate(context.Background(), id); err != nil {
		t.Fatalf("first ChargeCreate: %v", err)
	}
	liveWindowCount := readCreateRate(t, store, clk, id)

	// Move the wall clock back five minutes. The bucket label is derived from the
	// (now earlier) wall reading, so the next charge addresses a DIFFERENT,
	// empty cell and succeeds — it does not re-enter the live (full) bucket.
	clk.SetWallClock(gateStart.Add(-5 * time.Minute))

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate after setback: expected a fresh bucket to admit, got %v", err)
	}
	if rcpt == nil {
		t.Fatalf("ChargeCreate after setback: nil receipt")
	}
	// The live (full) bucket is unchanged — the setback did not extend it.
	clk.SetWallClock(gateStart)
	if got := readCreateRate(t, store, clk, id); got != liveWindowCount {
		t.Fatalf("live-window create-rate = %d after setback, want %d (unchanged)", got, liveWindowCount)
	}
}

// TestPropertyQuotaNoOvercommit is the mandatory NFR-named property: across a
// random interleaving of ChargeCreate and Receipt.Apply (refund) calls, the
// per-tenant concurrent counter NEVER exceeds the limit and NEVER goes negative,
// and a refused ChargeCreate leaves both counters unchanged.
func TestPropertyQuotaNoOvercommit(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		concLimit := int64(rapid.IntRange(1, 5).Draw(rt, "concLimit"))
		clk := state.NewFakeClock(gateStart)
		store := state.NewInMemory(clk)
		// Generous create-rate so the property isolates the concurrent invariant;
		// the create-rate is exercised by the setback test above.
		g := quota.NewGate(store, clk, quota.Limits{CreateRatePerCallerPerMin: 1_000_000, ConcurrentSessionsPerTenant: concLimit})
		id := state.Identity{Tenant: "t1", Caller: "c1"}
		concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id}

		var live []*quota.Receipt // receipts whose concurrent charge is still held

		readConc := func() int64 {
			v, err := store.ReadQuota(context.Background(), concKey)
			if err != nil {
				rt.Fatalf("ReadQuota: %v", err)
			}
			return v
		}

		steps := rapid.IntRange(1, 40).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			op := rapid.SampledFrom([]string{"charge", "refund"}).Draw(rt, "op")
			switch op {
			case "charge":
				before := readConc()
				rcpt, err := g.ChargeCreate(context.Background(), id)
				after := readConc()
				if err != nil {
					if !errors.Is(err, state.ErrQuotaExceeded) {
						rt.Fatalf("unexpected charge error: %v", err)
					}
					// A refused charge leaves the concurrent counter unchanged.
					if after != before {
						rt.Fatalf("refused charge moved concurrent counter %d -> %d", before, after)
					}
					if rcpt != nil {
						rt.Fatalf("refused charge returned a non-nil receipt")
					}
				} else {
					if after != before+1 {
						rt.Fatalf("successful charge moved concurrent counter %d -> %d (want +1)", before, after)
					}
					live = append(live, rcpt)
				}
			case "refund":
				if len(live) == 0 {
					continue
				}
				rcpt := live[len(live)-1]
				live = live[:len(live)-1]
				if err := rcpt.Apply(context.Background()); err != nil {
					rt.Fatalf("Receipt.Apply: %v", err)
				}
			}

			// Invariants after every step.
			c := readConc()
			if c > concLimit {
				rt.Fatalf("concurrent counter %d exceeds limit %d", c, concLimit)
			}
			if c < 0 {
				rt.Fatalf("concurrent counter went negative: %d", c)
			}
			if c != int64(len(live)) {
				rt.Fatalf("concurrent counter %d disagrees with held receipts %d", c, len(live))
			}
		}
	})
}
