// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package quota is the create-time quota gate (NFR-COST-06). It enforces a
// deployment-wide policy against the Store's atomic counters BEFORE any durable
// host state exists on the create path, and it does so through the atomic
// Store.Charge ONLY — never a Read-then-Charge, which is the forbidden TOCTOU
// window the Store doc warns against. A refused charge is refused-not-queued
// (there is no retry loop, no backoff) and leaves the counter unchanged.
//
// A single create consumes exactly two of the quota dimensions, charged IN ORDER:
// the per-caller create-rate (windowed through the injected Clock) THEN the
// per-tenant concurrent-session level. If the second charge is refused, the first
// is refunded BEFORE ChargeCreate returns, so the visible outcome of any refusal
// is zero net counter movement. On success ChargeCreate returns a Receipt that
// records exactly the two cells charged; the lifecycle pushes Receipt.Apply onto
// its unwind stack so a downstream failure refunds precisely what was charged —
// never a phantom decrement.
//
// The windowed dimension's bucket label is derived by truncating the Clock's Now
// to the window boundary and formatting it as an opaque, timezone-free string.
// The Store treats that label as an opaque key segment and does no time math on
// it, so a new window addresses a fresh zero-valued cell and a wall-clock setback
// yields a DIFFERENT (earlier) bucket label rather than re-entering the live
// bucket — a flood cannot exceed the per-window limit within one true window. No
// window math ever subtracts a persisted timestamp.
//
// The package imports internal/state for the Store seam, the Clock, and the
// quota key types; it holds no concrete database type.
package quota

import (
	"context"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// unwindStepTimeout bounds each refund step so a refund running under a detached
// context cannot wedge indefinitely on a slow Store. It mirrors the bounded
// per-step discipline the runtime finalizer uses.
const unwindStepTimeout = 5 * time.Second

// minuteWindowLayout formats an instant truncated to the minute as a timezone-free
// opaque bucket label. It is identical across the in-memory and Postgres Stores
// and across restarts, and a wall-clock setback maps to an earlier label rather
// than the live bucket.
const minuteWindowLayout = "2006-01-02T15:04Z"

// dayWindowLayout is the per-day analogue of minuteWindowLayout, for the day-level
// windowed dimensions charged on their own later-phase events (not at create).
const dayWindowLayout = "2006-01-02Z"

// Limits is the deployment-wide quota policy: the ceiling per dimension. The
// Store holds the counters but knows no limit; the policy lives here, above the
// Store. The full policy is whole (every dimension has a ceiling), but a single
// create touches only the two create-time dimensions — the others are charged on
// their own events (an MCP call, a storage provision, egress accounting) through
// the same atomic Store.Charge in later phases.
type Limits struct {
	// ConcurrentSessionsPerTenant caps live (RESERVED+ACTIVE) sessions per tenant.
	ConcurrentSessionsPerTenant int64
	// MCPCallsPerMinPerTenant caps MCP calls per tenant per minute (charged on the
	// MCP-call event, not at create).
	MCPCallsPerMinPerTenant int64
	// StorageGBPerTenant caps provisioned storage gigabytes per tenant (charged on
	// the storage-provision event, not at create).
	StorageGBPerTenant int64
	// EgressBytesPerDayPerTenant caps egress bytes per tenant per day (charged on
	// the egress-accounting event, not at create).
	EgressBytesPerDayPerTenant int64
	// CreateRatePerCallerPerMin caps create attempts per caller per minute — the
	// first of the two charges a create consumes, and the NFR-SEC-55 flood input.
	CreateRatePerCallerPerMin int64
}

// minuteWindow derives the opaque per-minute QuotaKey.Window label through the
// injected Clock: UTC, truncated to the minute, formatted timezone-free. It is
// the only place the create-rate window label is produced, so the discipline
// (truncate, never subtract a persisted timestamp) lives in one spot.
func minuteWindow(clk state.Clock) string {
	return clk.Now().UTC().Truncate(time.Minute).Format(minuteWindowLayout)
}

// dayWindow derives the opaque per-day QuotaKey.Window label through the Clock,
// for the day-level windowed dimensions. It is unused on the create path (which
// charges only create-rate and concurrent) and exists so the day-window
// derivation is pinned in this package alongside minuteWindow for the later-phase
// charges.
func dayWindow(clk state.Clock) string {
	return clk.Now().UTC().Truncate(24 * time.Hour).Format(dayWindowLayout)
}

// Charged is one applied charge cell a Receipt can reverse EXACTLY. It records
// the QuotaKey the charge addressed and the delta actually applied, so the refund
// is a negative-delta Charge of the same cell — no more and no less than was
// charged.
type Charged struct {
	// Key is the exact counter cell the charge addressed (dim, identity, window).
	Key state.QuotaKey
	// Delta is the positive amount applied; the refund charges its negation.
	Delta int64
}

// Receipt is the quota stage's compensator. It refunds EXACTLY the cells
// ChargeCreate applied (a negative-delta Charge per cell, which the Store
// saturates at zero), reversing them in the opposite order they were charged.
// Apply is idempotent: it empties its recorded cells as it refunds, so a second
// Apply is a no-op. A refused create never produces a Receipt with a phantom
// cell, so unwind decrements only what was charged.
type Receipt struct {
	store   state.Store
	charged []Charged // append-ordered; refunded in reverse
}

// Apply reverses the recorded charges, each as a negative-delta Store.Charge,
// under a context detached from the caller's cancellation (context.WithoutCancel)
// with a per-step bounded timeout, so a cancelled request context cannot strand a
// charged counter. It refunds in reverse of the charge order and clears each cell
// as it goes, making a re-run a no-op. The first refund error is returned after
// attempting every remaining cell, so one slow cell cannot block the rest. A nil
// Receipt and an already-empty Receipt both return nil.
func (r *Receipt) Apply(ctx context.Context) error {
	if r == nil || len(r.charged) == 0 {
		return nil
	}
	base := context.WithoutCancel(ctx)
	cells := r.charged
	r.charged = nil // idempotent: clear before refunding so a re-run is a no-op

	var firstErr error
	for i := len(cells) - 1; i >= 0; i-- {
		c := cells[i]
		stepCtx, cancel := context.WithTimeout(base, unwindStepTimeout)
		_, err := r.store.Charge(stepCtx, c.Key, -c.Delta, 0)
		cancel()
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("quota: refund cell dim=%d: %w", c.Key.Dim, err)
		}
	}
	return firstErr
}

// Gate enforces the create-time quota set against the atomic Store.Charge ONLY.
// It holds the Store, the injected Clock (for the window label), and the
// deployment Limits. It is safe for concurrent use because every mutation goes
// through the Store's atomic Charge.
type Gate struct {
	store  state.Store
	clk    state.Clock
	limits Limits
}

// NewGate constructs a Gate bound to the Store, Clock, and deployment Limits.
func NewGate(store state.Store, clk state.Clock, limits Limits) *Gate {
	return &Gate{store: store, clk: clk, limits: limits}
}

// ChargeCreate applies the two create-time charges a single create consumes, IN
// ORDER:
//
//  1. DimCallerCreateRate +1, windowed via minuteWindow(clk), billed to the
//     caller, against Limits.CreateRatePerCallerPerMin; then
//  2. DimConcurrentSessions +1, level (empty Window), billed to the tenant,
//     against Limits.ConcurrentSessionsPerTenant.
//
// Each charge is an atomic state.Store.Charge with its limit. ChargeCreate NEVER
// calls ReadQuota — a Read-then-Charge is the forbidden TOCTOU. If the FIRST
// charge is refused (ErrQuotaExceeded) it returns immediately having moved no
// counter. If the SECOND is refused it REFUNDS the first (a negative-delta
// Charge) BEFORE returning, so the caller sees zero net counter movement
// (no-counter-on-refusal). On success it returns a *Receipt recording exactly the
// two cells charged, in charge order, for the lifecycle's unwind stack. Any
// non-quota Store failure (ErrStoreUnavailable) propagates after refunding any
// already-applied charge, treated by admission as a refusal.
func (g *Gate) ChargeCreate(ctx context.Context, id state.Identity) (*Receipt, error) {
	rateKey := state.QuotaKey{
		Dim:      state.DimCallerCreateRate,
		Identity: id,
		Window:   minuteWindow(g.clk),
	}
	if _, err := g.store.Charge(ctx, rateKey, 1, g.limits.CreateRatePerCallerPerMin); err != nil {
		// First charge refused or store-unavailable: nothing applied, nothing to
		// refund. Propagate the typed error unchanged for the caller to branch on.
		return nil, err
	}

	concKey := state.QuotaKey{
		Dim:      state.DimConcurrentSessions,
		Identity: id,
		Window:   "", // level dimension: empty window per the Store contract
	}
	if _, err := g.store.Charge(ctx, concKey, 1, g.limits.ConcurrentSessionsPerTenant); err != nil {
		// Second charge failed: refund the first so zero net counter moved, then
		// surface the typed error. The refund runs detached + bounded so a
		// cancelled request context cannot strand the create-rate counter.
		g.refundOne(ctx, rateKey)
		return nil, err
	}

	return &Receipt{
		store: g.store,
		charged: []Charged{
			{Key: rateKey, Delta: 1},
			{Key: concKey, Delta: 1},
		},
	}, nil
}

// refundOne reverses a single already-applied charge with a negative-delta
// Charge, detached from the caller's cancellation and bounded, so the partial
// charge cannot survive a refused create. A refund error is intentionally not
// surfaced over the original refusal: the caller's contract is the typed refusal,
// and the Store saturates a negative delta at zero so a retried refund is safe.
func (g *Gate) refundOne(ctx context.Context, key state.QuotaKey) {
	base := context.WithoutCancel(ctx)
	stepCtx, cancel := context.WithTimeout(base, unwindStepTimeout)
	defer cancel()
	_, _ = g.store.Charge(stepCtx, key, -1, 0)
}

// RefundConcurrent returns one per-tenant concurrent-session slot: a negative-delta
// Charge of the DimConcurrentSessions level cell, which the Store saturates at zero
// so the counter never goes negative even if called twice for one create. It is the
// SINGLE decrement both the lifecycle destroy path and the boot reconciler use, so a
// crashed-then-reclaimed RESERVED row does not leak the level counter upward (the
// reconciler→quota coupling). It runs detached from the caller's cancellation with a
// bounded per-step timeout, so a cancelled request context cannot strand the counter
// above the true live count. A negative delta is never refused, so a non-quota Store
// failure is the only error path; it is surfaced for the caller to log.
func (g *Gate) RefundConcurrent(ctx context.Context, id state.Identity) error {
	concKey := state.QuotaKey{
		Dim:      state.DimConcurrentSessions,
		Identity: id,
		Window:   "", // level dimension: empty window per the Store contract
	}
	base := context.WithoutCancel(ctx)
	stepCtx, cancel := context.WithTimeout(base, unwindStepTimeout)
	defer cancel()
	if _, err := g.store.Charge(stepCtx, concKey, -1, 0); err != nil {
		return fmt.Errorf("quota: refund concurrent: %w", err)
	}
	return nil
}

// ReconcileConcurrent heals a drifted per-tenant DimConcurrentSessions cell down to
// liveCount — the true number of live (RESERVED+ACTIVE) rows the boot reconciler
// counted for the tenant. The cell is a separate lock domain from the rows and is
// only ever moved by +1 charge / -1 refund; if a refund is lost (an aborted create
// whose unwind refund failed and was swallowed), the cell drifts ABOVE the live-row
// count with no row to reclaim, so the row-based reconcile cannot correct it and the
// counter permanently over-counts until it wedges the tier cap. This recomputes the
// truth from the rows and refunds exactly the surplus (cell - liveCount) as a single
// negative-delta Charge, so a restart restores cell-truth regardless of past refund
// reliability. It only corrects DOWN: a cell at or below liveCount is left untouched
// (the reconciler never charges the cell up — a genuine live session already holds
// its charge, and inflating would itself leak). It returns the surplus it refunded
// (0 when there was no drift) so the reconciler can log how much it healed. It runs
// through the injected Clock/Store contract with no time math — the correction is a
// count comparison, never a timestamp subtraction.
func (g *Gate) ReconcileConcurrent(ctx context.Context, id state.Identity, liveCount int64) (int64, error) {
	concKey := state.QuotaKey{
		Dim:      state.DimConcurrentSessions,
		Identity: id,
		Window:   "", // level dimension: empty window per the Store contract
	}
	current, err := g.store.ReadQuota(ctx, concKey)
	if err != nil {
		return 0, fmt.Errorf("quota: reconcile concurrent read: %w", err)
	}
	surplus := current - liveCount
	if surplus <= 0 {
		return 0, nil // no drift (or an under-count the heal must never inflate)
	}
	if _, err := g.store.Charge(ctx, concKey, -surplus, 0); err != nil {
		return 0, fmt.Errorf("quota: reconcile concurrent refund: %w", err)
	}
	return surplus, nil
}
