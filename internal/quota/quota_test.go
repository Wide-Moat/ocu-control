// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package quota_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// gateStart is the fixed instant the quota tests anchor their FakeClock on, so
// the per-minute window label is reproducible across runs.
var gateStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// errChargeInjected is the sentinel a faulting Charge returns, so a test can
// assert by identity that the refund path surfaced THIS error and not some other.
var errChargeInjected = errors.New("quota_test: injected Charge fault")

// chargeRecord captures one Charge call's arguments. The refund paths saturate at
// zero in the in-memory Store, so the OBSERVABLE counter cannot distinguish a
// correct refund (delta -1, limit 0) from an over-refund (delta -2) or a mutated
// limit arg — the mutation is masked by saturation. Recording the exact triple a
// refund issued lets a test pin the delta the compensator actually charged, which
// is the only way to kill the delta-magnitude mutants on the refund path.
type chargeRecord struct {
	Key   state.QuotaKey
	Delta int64
	Limit int64
}

// chargeRecorderStore wraps an in-memory Store, records every Charge it forwards,
// and can optionally fault negative-delta (refund) charges so the refund-error
// paths are exercised. It is a single fixture covering both gaps the refund path
// leaves: delta-magnitude (via Records) and error-propagation (via failNegCharge).
type chargeRecorderStore struct {
	state.Store
	records       []chargeRecord
	failNegCharge bool // when set, every negative-delta (refund) Charge returns errChargeInjected
}

func (s *chargeRecorderStore) Charge(ctx context.Context, key state.QuotaKey, delta, limit int64) (int64, error) {
	s.records = append(s.records, chargeRecord{Key: key, Delta: delta, Limit: limit})
	if s.failNegCharge && delta < 0 {
		return 0, errChargeInjected
	}
	return s.Store.Charge(ctx, key, delta, limit)
}

// negativeDeltaRecords returns only the refund (negative-delta) Charge records, in
// the order they were issued — the create-path positive charges are filtered out
// so a refund assertion is not confused by the preceding +1 charges.
func (s *chargeRecorderStore) negativeDeltaRecords() []chargeRecord {
	var out []chargeRecord
	for _, r := range s.records {
		if r.Delta < 0 {
			out = append(out, r)
		}
	}
	return out
}

// newRecorderGate builds a Gate over a chargeRecorderStore (itself over a fresh
// in-memory Store), returning both so a test can drive the gate and then inspect
// the exact Charge triples the refund path issued.
func newRecorderGate(t *testing.T, clk state.Clock, limits quota.Limits) (*quota.Gate, *chargeRecorderStore) {
	t.Helper()
	rec := &chargeRecorderStore{Store: state.NewInMemory(clk)}
	return quota.NewGate(rec, clk, limits), rec
}

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

// TestReceiptApplyReturnsFirstRefundError proves Receipt.Apply CAPTURES and RETURNS
// a refund error rather than discarding it. A faulting Store fails the negative-delta
// refund Charge; Apply must surface the injected error (wrapped). The earlier
// TestReceiptApplyRefundsBothCells only asserts the happy-path counter reaches zero,
// so the error-capture assignment was never load-bearing — a mutant that drops the
// firstErr assignment survived. This pins the return contract.
func TestReceiptApplyReturnsFirstRefundError(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	// Fault the refund: every negative-delta Charge now errors.
	rec.failNegCharge = true

	err = rcpt.Apply(context.Background())
	if err == nil {
		t.Fatalf("Receipt.Apply: returned nil despite a failing refund Charge; the refund error was swallowed")
	}
	if !errors.Is(err, errChargeInjected) {
		t.Fatalf("Receipt.Apply: error %v does not wrap the injected Charge fault", err)
	}
}

// TestReceiptApplyReturnsFirstNotLastRefundError proves Apply returns the FIRST
// refund error and keeps attempting the remaining cells (the "first error after
// trying every remaining cell" contract). With BOTH cells faulting, Apply must
// still issue a Charge for every cell (so one slow/failing cell cannot block the
// rest) yet return only the first captured error — pinning the firstErr==nil guard
// that a mutant relaxed to `true` (which would overwrite with the LAST error).
func TestReceiptApplyReturnsFirstNotLastRefundError(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	rec.failNegCharge = true
	// Reset the record log so we count only the refund attempts.
	rec.records = nil

	if err := rcpt.Apply(context.Background()); err == nil {
		t.Fatalf("Receipt.Apply: returned nil despite failing refunds")
	}
	// Every recorded cell must have been attempted even though the first one failed:
	// a Receipt from ChargeCreate holds two cells, so two refund Charges must fire.
	refunds := rec.negativeDeltaRecords()
	if len(refunds) != 2 {
		t.Fatalf("Receipt.Apply issued %d refund charges, want 2 (a failing cell must not abort the rest)", len(refunds))
	}
	// The first-vs-last error identity is asserted in TestReceiptApplyReturnsFirstErrorByDim;
	// here the contract under test is only that a failing cell does not abort the rest.
}

// TestReceiptApplyReturnsFirstErrorByDim sharpens the first-not-last contract: it
// asserts the returned error names the FIRST-refunded cell's dimension (the
// concurrent level cell, refunded first because refunds run in reverse of charge
// order). A mutant that relaxes `firstErr == nil` to `true` overwrites firstErr on
// every iteration, so the returned error would name the create-rate dim instead —
// this asserts the dim and kills that mutant directly.
func TestReceiptApplyReturnsFirstErrorByDim(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	rec.failNegCharge = true

	err = rcpt.Apply(context.Background())
	if err == nil {
		t.Fatalf("Receipt.Apply: nil error despite failing refunds")
	}
	// The first cell refunded is the LAST cell charged: the concurrent (level) cell.
	// The error message embeds its dim. If the first-error guard were relaxed, the
	// final (create-rate) dim would win instead.
	wantDim := fmt.Sprintf("dim=%d", state.DimConcurrentSessions)
	dontWantDim := fmt.Sprintf("dim=%d", state.DimCallerCreateRate)
	if msg := err.Error(); !strings.Contains(msg, wantDim) || strings.Contains(msg, dontWantDim) {
		t.Fatalf("Receipt.Apply error = %q; want it to name the FIRST-refunded cell %q, not the last %q", msg, wantDim, dontWantDim)
	}
}

// TestRefundConcurrentPropagatesStoreError proves RefundConcurrent surfaces a
// non-quota Store failure (its sole error path — a negative delta is never quota-
// refused) rather than swallowing it. TestRefundConcurrentDecrementsAndSaturates
// only exercised the happy path, so the `return fmt.Errorf(...)` was never asserted
// and a mutant that drops it survived. This pins the propagation contract the
// destroy path and the boot reconciler both rely on to log a stranded counter.
func TestRefundConcurrentPropagatesStoreError(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rec.failNegCharge = true // RefundConcurrent's decrement is a negative-delta Charge
	err := g.RefundConcurrent(context.Background(), id)
	if err == nil {
		t.Fatalf("RefundConcurrent: returned nil despite a failing Charge; the store error was swallowed")
	}
	if !errors.Is(err, errChargeInjected) {
		t.Fatalf("RefundConcurrent: error %v does not wrap the injected Charge fault", err)
	}
}

// TestRefundConcurrentChargesExactlyMinusOne pins the EXACT refund delta and limit
// RefundConcurrent issues: a single -1 charge with limit 0 (saturate, never refuse).
// The in-memory Store saturates at zero, so a mutated delta (-1 -> -2) or limit (0
// -> 1) is invisible in the counter — only inspecting the issued triple kills those
// mutants. It returns precisely one slot, no more, against the level cell.
func TestRefundConcurrentChargesExactlyMinusOne(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rec.records = nil // isolate the refund charge
	if err := g.RefundConcurrent(context.Background(), id); err != nil {
		t.Fatalf("RefundConcurrent: %v", err)
	}
	refunds := rec.negativeDeltaRecords()
	if len(refunds) != 1 {
		t.Fatalf("RefundConcurrent issued %d negative charges, want exactly 1", len(refunds))
	}
	r := refunds[0]
	if r.Delta != -1 {
		t.Fatalf("RefundConcurrent delta = %d, want -1 (one slot, never more)", r.Delta)
	}
	if r.Limit != 0 {
		t.Fatalf("RefundConcurrent limit = %d, want 0 (negative delta saturates, never refuses)", r.Limit)
	}
	if r.Key.Dim != state.DimConcurrentSessions {
		t.Fatalf("RefundConcurrent dim = %d, want DimConcurrentSessions", r.Key.Dim)
	}
}

// TestReconcileConcurrentHealsDriftDown pins the boot cell-reconcile: a cell drifted
// ABOVE the true live count is corrected DOWN to that count, and the surplus it
// refunded is returned. It kills the mutants on the surplus computation and the
// down-only guard: a mutant that flips the surplus sign, drops the refund, or changes
// the comparison would leave the cell inflated or drive it below the live count.
func TestReconcileConcurrentHealsDriftDown(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	inner := state.NewInMemory(clk)
	g := quota.NewGate(inner, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 100})
	store := inner
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	// Inflate the cell to 5; the true live count is 2 (three phantom charges).
	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id}
	if _, err := store.Charge(context.Background(), concKey, 5, 1000); err != nil {
		t.Fatalf("seed inflated cell: %v", err)
	}

	surplus, err := g.ReconcileConcurrent(context.Background(), id, 2)
	if err != nil {
		t.Fatalf("ReconcileConcurrent: %v", err)
	}
	if surplus != 3 {
		t.Fatalf("ReconcileConcurrent refunded surplus = %d, want 3 (5 - 2)", surplus)
	}
	if got := readConcurrent(t, store, id); got != 2 {
		t.Fatalf("cell after reconcile = %d, want 2 (healed down to the live count)", got)
	}
}

// TestReconcileConcurrentNoDriftIsNoOp pins the down-only guard on the two boundary
// cases: a cell that already MATCHES the live count and a cell BELOW it (an
// under-count the heal must never inflate). Both leave the cell untouched and refund
// nothing. It kills a mutant that flips the surplus<=0 guard (which would charge the
// cell UP or drive a matched cell down).
func TestReconcileConcurrentNoDriftIsNoOp(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	inner := state.NewInMemory(clk)
	g := quota.NewGate(inner, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 100})
	store := inner
	id := state.Identity{Tenant: "t1", Caller: "c1"}
	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id}

	// Matched: cell == liveCount.
	if _, err := store.Charge(context.Background(), concKey, 2, 1000); err != nil {
		t.Fatalf("seed matched cell: %v", err)
	}
	surplus, err := g.ReconcileConcurrent(context.Background(), id, 2)
	if err != nil {
		t.Fatalf("ReconcileConcurrent matched: %v", err)
	}
	if surplus != 0 {
		t.Fatalf("matched reconcile surplus = %d, want 0 (no drift)", surplus)
	}
	if got := readConcurrent(t, store, id); got != 2 {
		t.Fatalf("matched cell after reconcile = %d, want 2 (untouched)", got)
	}

	// Below: liveCount exceeds the cell — the heal must NOT charge up.
	surplus, err = g.ReconcileConcurrent(context.Background(), id, 5)
	if err != nil {
		t.Fatalf("ReconcileConcurrent below: %v", err)
	}
	if surplus != 0 {
		t.Fatalf("below-count reconcile surplus = %d, want 0 (never inflates)", surplus)
	}
	if got := readConcurrent(t, store, id); got != 2 {
		t.Fatalf("below-count cell after reconcile = %d, want 2 (never charged up)", got)
	}
}

// TestReconcileConcurrentPropagatesRefundError pins the refund-error path: when the
// down-correcting Charge itself fails, ReconcileConcurrent surfaces the error wrapped
// and does NOT report a surplus it did not actually refund. It kills the mutant that
// drops the `return 0, err` on the refund Charge (which would claim a heal that never
// landed, leaving the cell still drifted while the reconciler reports success).
func TestReconcileConcurrentPropagatesRefundError(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 100})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	// Inflate the cell so there IS a surplus to refund, then fault the refund Charge.
	concKey := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id}
	if _, err := rec.Store.Charge(context.Background(), concKey, 5, 1000); err != nil {
		t.Fatalf("seed inflated cell: %v", err)
	}
	rec.failNegCharge = true

	surplus, err := g.ReconcileConcurrent(context.Background(), id, 2)
	if err == nil {
		t.Fatal("ReconcileConcurrent with a failing refund Charge returned nil; want the store error surfaced")
	}
	if surplus != 0 {
		t.Fatalf("ReconcileConcurrent on a failed refund reported surplus = %d, want 0 (no heal actually landed)", surplus)
	}
}

// TestReconcileConcurrentPropagatesReadError pins the read-error path: a failing
// ReadQuota is surfaced wrapped (not swallowed, not treated as zero — which would
// spuriously refund the whole cell). It kills a mutant that drops the read-error
// branch.
func TestReconcileConcurrentPropagatesReadError(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g := quota.NewGate(state.NewInMemory(clk), clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 100})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a cancelled context makes the Store's ReadQuota fail closed
	surplus, err := g.ReconcileConcurrent(ctx, id, 0)
	if err == nil {
		t.Fatal("ReconcileConcurrent with a failing ReadQuota returned nil; want the store error surfaced")
	}
	// On the read-error path the surplus MUST be the zero value, never a sentinel like
	// -1: the caller reads it as "how much was healed", so a non-zero surplus on a
	// failed read would misreport a heal that never happened. Pinning it kills the
	// mutant that returns -1 on the read-error branch.
	if surplus != 0 {
		t.Fatalf("ReconcileConcurrent read-error surplus = %d, want 0 (no heal on a failed read)", surplus)
	}
}

// TestReceiptApplyChargesExactChargedDeltaPerCell pins the per-cell refund delta
// the unwind compensator issues: each cell is refunded by EXACTLY the negation of
// what was charged (-1), not more. A mutant that records Delta:2 in the Receipt (or
// negates to -2 on the Charge) over-refunds, which the saturating Store hides at a
// counter of 1 — so this inspects the issued triples instead. Refunds run in
// reverse charge order: concurrent first, then create-rate.
func TestReceiptApplyChargesExactChargedDeltaPerCell(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(gateStart)
	g, rec := newRecorderGate(t, clk, quota.Limits{CreateRatePerCallerPerMin: 10, ConcurrentSessionsPerTenant: 10})
	id := state.Identity{Tenant: "t1", Caller: "c1"}

	rcpt, err := g.ChargeCreate(context.Background(), id)
	if err != nil {
		t.Fatalf("ChargeCreate: %v", err)
	}
	rec.records = nil // isolate the two refund charges from the two create charges
	if err := rcpt.Apply(context.Background()); err != nil {
		t.Fatalf("Receipt.Apply: %v", err)
	}
	refunds := rec.negativeDeltaRecords()
	if len(refunds) != 2 {
		t.Fatalf("Receipt.Apply issued %d refund charges, want 2 (one per charged cell)", len(refunds))
	}
	// Reverse charge order: concurrent (level) cell first, then create-rate.
	if refunds[0].Key.Dim != state.DimConcurrentSessions {
		t.Fatalf("first refund dim = %d, want DimConcurrentSessions (reverse order)", refunds[0].Key.Dim)
	}
	if refunds[1].Key.Dim != state.DimCallerCreateRate {
		t.Fatalf("second refund dim = %d, want DimCallerCreateRate (reverse order)", refunds[1].Key.Dim)
	}
	for i, r := range refunds {
		if r.Delta != -1 {
			t.Fatalf("refund[%d] delta = %d, want -1 (exactly the negation of the +1 charged)", i, r.Delta)
		}
		if r.Limit != 0 {
			t.Fatalf("refund[%d] limit = %d, want 0 (negative delta saturates)", i, r.Limit)
		}
	}
}
