// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrRevokeUnbound is returned when Revoke is asked for an EgressBinding whose
// FilesystemID was never recorded at mint. The finalizer treats this as a
// satisfied no-op (there is no live jti to revoke), so it is wrapped for
// diagnostics but the teardown path does not fail on it.
var ErrRevokeUnbound = errors.New("cred: no minted jti bound to that egress filesystem_id")

// Revoker is the host-side reclamation index the below-seam finalizer step-1
// ("revoke session JWT") calls. It records the jti minted for a session against
// the session's FilesystemID, so a revoke can mark that jti dead even though the
// frozen session row does not persist the jti. The JWKS Verifier consults
// IsRevoked. Every liveness mark is read against the injected monotonic Clock,
// so a wall-clock setback never un-revokes a dead jti (NFR-SEC-48). The Revoker
// lives in cred (custody), but its CALL SITE is docker/teardown step-1 — the
// canon-fixed ordering — not a lifecycle-parallel path. The index is in-memory;
// a restart-survivable revocation store is a later-phase durability concern.
type Revoker struct {
	mu   sync.Mutex
	clk  state.Clock
	dead map[string]time.Time // jti -> monotonic mark of revocation
	bind map[string]string    // FilesystemID -> jti recorded at mint
}

// NewRevoker builds an empty Revoker on the injected monotonic Clock. A nil
// clock is a programmer error; the constructor falls back to the system clock so
// a misconfigured caller never silently disables liveness, but production wiring
// always passes the shared injected Clock.
func NewRevoker(clk state.Clock) *Revoker {
	if clk == nil {
		clk = state.SystemClock()
	}
	return &Revoker{
		clk:  clk,
		dead: make(map[string]time.Time),
		bind: make(map[string]string),
	}
}

// Record indexes the jti against the FilesystemID at mint time, so the finalizer
// (which receives EgressBinding.FilesystemID) can revoke without the session row
// carrying the jti. A later Record for the same FilesystemID supersedes the
// binding — the freshest mint is the one a teardown revokes. Empty inputs are
// ignored (there is nothing to bind).
func (r *Revoker) Record(filesystemID, jti string) {
	if filesystemID == "" || jti == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bind[filesystemID] = jti
}

// Revoke is the finalizer step-1 effect: mark the session's jti dead, keyed off
// the EgressBinding the step already holds. It is idempotent — a re-run of the
// finalizer revokes an already-dead jti without error — and the dead mark is
// monotonic, stamped from the injected Clock, so a wall-clock setback never
// resurrects the token. An unrecorded FilesystemID returns ErrRevokeUnbound,
// which the finalizer treats as a satisfied no-op (nothing live to revoke).
func (r *Revoker) Revoke(ctx context.Context, bind runtime.EgressBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	jti, ok := r.bind[bind.FilesystemID]
	if !ok {
		return ErrRevokeUnbound
	}
	if _, already := r.dead[jti]; !already {
		r.dead[jti] = r.clk.Now()
	}
	return nil
}

// IsRevoked is what the JWKS Verifier consults. A revoked jti is permanently
// dead: the mark is monotonic, so a SetWallClock setback after a revoke never
// reports the jti as live again.
func (r *Revoker) IsRevoked(jti string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, dead := r.dead[jti]
	return dead
}
