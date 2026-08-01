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

// ErrRevokeUnbound is returned when Revoke is asked to revoke a session whose
// bind-key was never recorded at mint. The finalizer treats this as a satisfied
// no-op (there is no live jti to revoke), but it is a DISTINCT audited outcome
// (RevokeNoneBound), never dissolved into a blanket "success" — a revoke that
// bound nothing is evidence, not silence.
var ErrRevokeUnbound = errors.New("cred: no minted jti bound to that session bind-key")

// BindKey derives the single index key that BOTH the mint-side Record and the
// teardown-side Revoke key the revocation index on. It is the ONE derivation both
// call sites share, so the record-key and the lookup-key are equal BY
// CONSTRUCTION (compile-time), never by a value collision between two
// independently chosen keys. The input is the host-derived session identity —
// the registry key the signer owns at mint and the finalizer re-derives from the
// session row — NEVER a body-supplied FilesystemID (NFR-SEC-43): the mint scope's
// FilesystemID is irrelevant to which jti a teardown revokes. Keeping it a named
// derivation (rather than a bare map access) is what makes a key-drift regression
// impossible: swap either side off BindKey and the two keys no longer agree, and
// the drift test goes red.
func BindKey(sessionKey string) string {
	// The identity of the host-derived session key IS the bind key; the function
	// exists so both sides provably route through the same derivation. A future
	// change to how the index is keyed (namespacing, hashing) changes it HERE, for
	// both sides at once, and cannot drift them apart.
	return sessionKey
}

// Revoker is the host-side reclamation index the below-seam finalizer step-1
// ("revoke session JWT") calls. It records the jti minted for a session against
// the session's BindKey, so a revoke can mark that jti dead even though the
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
	bind map[string][]string  // BindKey(sessionKey) -> jtis recorded at mint (one per mount)
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
		bind: make(map[string][]string),
	}
}

// Record indexes the jti against BindKey(sessionKey) at mint time, so the
// finalizer (which re-derives the same session key from the session row) can
// revoke without the session row carrying the jti. Records for the same session
// key ACCUMULATE: a session mints one weak Storage-JWT per mount (the two-mount
// layout mints two), and a teardown must revoke every one of them - a
// last-write-wins binding would leave every earlier mount's jti alive past the
// session. A duplicate jti is recorded once. Empty inputs are ignored (there is
// nothing to bind). The FIRST argument is the host-derived session key, NOT a
// FilesystemID; both call sites route through BindKey so record-key ≡ lookup-key
// by construction.
func (r *Revoker) Record(sessionKey, jti string) {
	if sessionKey == "" || jti == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := BindKey(sessionKey)
	for _, bound := range r.bind[key] {
		if bound == jti {
			return
		}
	}
	r.bind[key] = append(r.bind[key], jti)
}

// Revoke is the finalizer step-1 effect: mark the session's jti dead, keyed off
// the host-derived session identity the EgressBinding.Name already carries — the
// SAME BindKey the mint recorded under, so the lookup cannot drift from the
// record. It is idempotent — a re-run revokes an already-dead jti without error —
// and the dead mark is monotonic, stamped from the injected Clock, so a
// wall-clock setback never resurrects the token. A session whose bind-key was
// never recorded returns (RevokeNoneBound, ErrRevokeUnbound): the finalizer
// treats it as a satisfied no-op BUT audits the none_bound outcome, so a
// silently-missed revoke leaves evidence. The revoke lookup is keyed on
// bind.Name (the session identity), never on bind.FilesystemID (a mint scope
// irrelevant to which jti to revoke).
func (r *Revoker) Revoke(ctx context.Context, bind runtime.EgressBinding) (runtime.RevokeOutcome, error) {
	if err := ctx.Err(); err != nil {
		return runtime.RevokeNoneBound, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	jtis, ok := r.bind[BindKey(string(bind.Name))]
	if !ok || len(jtis) == 0 {
		return runtime.RevokeNoneBound, ErrRevokeUnbound
	}
	marked := false
	for _, jti := range jtis {
		if _, already := r.dead[jti]; already {
			continue
		}
		r.dead[jti] = r.clk.Now()
		marked = true
	}
	if !marked {
		return runtime.RevokeAlreadyDead, nil
	}
	return runtime.RevokeMarkedDead, nil
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
