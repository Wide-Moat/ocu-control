// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package admit is the operator-ingress admission gate that keeps the kill-switch
// revoke path inside its NFR-SEC-01 ≤30s p99 SLA while the control plane is under
// concurrent saturation, including a flood on the operator ingress itself
// (NFR-SEC-55). It bounds how many operator requests run at once and RESERVES a
// sub-pool of that capacity for the priority (revoke / DENY-ALL / resume) routes,
// so a create/read flood on the operator socket consumes only the GENERAL slots and
// can never starve a revoke.
//
// The gate is two counting semaphores built on buffered channels: `general` sized
// to the everyday operator concurrency, and `reserved` sized to the guaranteed
// revoke headroom. A ClassPriority acquire takes a reserved slot FIRST and falls
// back to a general slot only when the reserved pool is momentarily empty — the
// reservation is a floor for priority, never a ceiling. A ClassGeneral acquire may
// take ONLY a general slot, so the reserved headroom is invisible to the flood.
// This is the structural half of SEC-55; the per-caller token bucket that bounds a
// single operator principal's ingress rate is the gate's companion (rate.go).
//
// The package is a leaf: it imports nothing internal and holds no HTTP or transport
// type, so the operator adapter can wrap any handler with it and a unit test can
// drive the admission decision without a socket.
package admit

import "context"

// Class selects which admission pool a request draws from. It is set by the
// operator adapter from the request's route: the revoke/DENY-ALL/resume routes are
// ClassPriority, every other operator route is ClassGeneral.
type Class uint8

const (
	// ClassGeneral is the everyday operator route (create, read, quota-override,
	// mcp-key mint). It may take only a general slot, so a flood of these can exhaust
	// the general pool without ever touching the reserved revoke headroom.
	ClassGeneral Class = iota
	// ClassPriority is the kill-switch family (revoke-one, revoke-all, resume-all).
	// It takes a reserved slot first and a general slot only as a fallback, so it is
	// admitted even when every general slot is held by an in-flight flood.
	ClassPriority
)

// Gate bounds concurrent operator requests with a reserved priority sub-pool. A
// zero Gate is unusable; build one with NewGate. It is safe for concurrent use —
// the two channels are the only state and channel ops are the synchronization.
type Gate struct {
	general  chan struct{}
	reserved chan struct{}
}

// NewGate builds a gate with `general` everyday slots and `reserved` slots held
// back for the priority routes. A non-positive size yields an empty pool of that
// class: NewGate(n, 0) is a plain bounded semaphore with no reservation, and a
// zero general pool forces every general request to wait or refuse. The total
// concurrency ceiling is general+reserved.
func NewGate(general, reserved int) *Gate {
	if general < 0 {
		general = 0
	}
	if reserved < 0 {
		reserved = 0
	}
	return &Gate{
		general:  make(chan struct{}, general),
		reserved: make(chan struct{}, reserved),
	}
}

// Acquire admits a request of the given class, blocking until a slot is free or ctx
// is done. It returns a release func and true on admission; on ctx cancellation (or
// a deadline) it returns a no-op func and false, and the caller must refuse the
// request rather than run it. The release func returns the exact slot that was
// taken (reserved or general) and is idempotent-safe to call exactly once.
//
// A ClassPriority acquire first tries the reserved pool without blocking; only if
// the reserved pool is momentarily empty does it wait on EITHER pool, so it is
// never blocked behind a general flood while reserved capacity is free. A
// ClassGeneral acquire only ever waits on the general pool.
func (g *Gate) Acquire(ctx context.Context, class Class) (release func(), ok bool) {
	if class == ClassPriority {
		// Fast path: a free reserved slot admits immediately, even under full general
		// saturation. This is the SEC-55 guarantee.
		select {
		case g.reserved <- struct{}{}:
			return func() { <-g.reserved }, true
		default:
		}
		// Reserved momentarily empty: wait on either pool (reserved OR a spare
		// general slot), honoring ctx. A priority request may use a free general slot
		// — the reservation is a floor, not a ceiling.
		select {
		case g.reserved <- struct{}{}:
			return func() { <-g.reserved }, true
		case g.general <- struct{}{}:
			return func() { <-g.general }, true
		case <-ctx.Done():
			return func() {}, false
		}
	}

	// General: only a general slot, honoring ctx.
	select {
	case g.general <- struct{}{}:
		return func() { <-g.general }, true
	case <-ctx.Done():
		return func() {}, false
	}
}
