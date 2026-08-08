// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package warmclaim is the neutral seam the lifecycle uses to try a warm-pool
// claim on the create path, without importing the docker provider or the pool's
// concrete types. The daemon wires a Pool (backed by warmpool.Pool) and a
// Claimer (backed by docker.WarmFactory) into the Manager; both nil on the
// minimal shelf, where the create path is cold-only.
package warmclaim

import (
	"context"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtime/warmpool"
)

// Profile keys a warm-pool lookup. The lifecycle derives it from the resolved
// create input (image + hard caps + storage/FUSE posture) — the same fields the
// pool bakes at placeholder create, so a claim is only served a compatible unit.
type Profile = warmpool.Profile

// Unit is the opaque pooled unit a Get returns and a Claim/Dispose consumes.
type Unit = warmpool.Unit

// Pool is the warm-pool lookup + return the create path uses. A nil Pool (the
// minimal shelf) means every create is cold. Get is non-blocking: a miss falls
// straight through to the cold path.
type Pool interface {
	// Get removes and returns a warm unit for the profile, or false if none is
	// ready. The unit's ownership transfers wholly to the caller: on a hit the
	// caller MUST eventually Claim it (making it live) or Dispose/Put it (returning
	// or destroying it), else it leaks.
	Get(profile Profile) (Unit, bool)
	// Put re-offers a PRISTINE, never-claimed unit to the pool (the create-unwind
	// compensator's Branch A). It is non-blocking: if the profile's ready channel
	// is full or the pool is closed, the unit is destroyed instead so it never
	// leaks. A unit that was Claim-attempted must NEVER be Put (it is renamed /
	// specialized / possibly started and structurally unreturnable — NFR-SEC-68).
	Put(u Unit)
}

// Claimer converts a pooled unit into a live session, and disposes an unclaimed
// one. It is satisfied by docker.WarmFactory.
type Claimer interface {
	// Claim specializes a pooled unit's handoff to the real host-attested identity
	// BEFORE the guest boots (NFR-SEC-69), renames + networks + starts it, and
	// returns the live Sandbox handle (carrying its SockDirRoot) plus the
	// specialized handoff material for the session row. realPubKey is the
	// DEPLOYMENT-FIXED exec verify key (host-derived, never per-session or body).
	Claim(ctx context.Context, u Unit, realName runtime.SessionName, realPubKey []byte, egress runtime.EgressPolicy) (runtime.Sandbox, runtime.HandoffMaterial, error)
	// Dispose force-removes a unit's container and unstages its handoff root — the
	// create-unwind compensator's disposal path when the unit cannot be returned
	// (Branch B: claim-attempted) or the pool refused a Put. Idempotent.
	Dispose(ctx context.Context, u Unit) error
}
