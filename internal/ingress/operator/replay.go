// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// errOutsideWindow and errReplayed are the two ways an otherwise well-signed
// revoke is refused: its issuance is too old or too far ahead to accept, or its
// exact signature was already presented. The contract answers 409 for both,
// distinctly from the 401 an unverifiable signature earns, so an operator can
// tell a clock problem from a forged call.
// defaultSOARReplayWindow is the contract's
// x-ocu-anti-replay-window-seconds-default: 300s either side of host time. It is
// a tolerance for peer clock skew traded against how long a captured revoke
// stays presentable, so a deployment may narrow or widen it.
const defaultSOARReplayWindow = 300 * time.Second

var (
	errOutsideWindow = errors.New("operator: issued_at outside the anti-replay acceptance window")
	errReplayed      = errors.New("operator: this revoke issuance was already presented")
)

// replayGuard enforces the issued_at acceptance window and remembers the
// signatures it has admitted, so a captured revoke cannot be re-presented while
// its issuance is still inside the window.
//
// It lives HERE, in the adapter, rather than inside the SOARVerifier
// (ADR-0039): the verifier is the shelf-swap seam — webhook signature now,
// SPIFFE SVID later — while replay policy is the surface's own contract
// semantics and is identical whichever verifier is wired. Keeping it out here
// means a deployment that swaps shelves cannot lose replay protection.
//
// The caller MUST verify the signature before calling admit. Admitting an
// unverified issuance would let anyone who reaches the operator socket poison
// the cache with a forged future timestamp and block the legitimate revoke — a
// denial of service on the kill path.
type replayGuard struct {
	clock  state.Clock
	window time.Duration

	mu   sync.Mutex
	seen map[[sha256.Size]byte]time.Time
}

// newReplayGuard builds a guard accepting issuances within window either side of
// the host clock.
func newReplayGuard(clock state.Clock, window time.Duration) *replayGuard {
	return &replayGuard{
		clock:  clock,
		window: window,
		seen:   make(map[[sha256.Size]byte]time.Time),
	}
}

// admit reports whether this issuance may proceed, recording it when it may.
//
// issuedAt is the RFC 3339 text exactly as it arrived — the same bytes the
// signature covers. sig is the verified signature, which keys the cache:
// Ed25519 is deterministic, so a replayed revoke is byte-identical and keys
// cleanly, while two genuinely distinct revokes never collide.
func (g *replayGuard) admit(issuedAt string, sig []byte) error {
	issued, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil {
		// Fail closed: without a parseable instant the window check cannot run,
		// and admitting would skip the guard entirely.
		return fmt.Errorf("%w: issued_at %q is not an RFC 3339 instant: %v",
			errOutsideWindow, issuedAt, err)
	}

	now := g.clock.Now()
	skew := now.Sub(issued)
	if skew < 0 {
		skew = -skew
	}
	// The bound is inclusive: an issuance exactly at the limit is a legitimate
	// revoke from a peer whose clock sits one window away, not an attack.
	if skew > g.window {
		return fmt.Errorf("%w: issued_at %s is %s from host time %s (window %s)",
			errOutsideWindow, issuedAt, skew, now.Format(time.RFC3339), g.window)
	}

	// The key is a digest rather than the signature bytes: it bounds each entry
	// to a fixed size regardless of what a caller sends, and the map never holds
	// credential-shaped material.
	key := sha256.Sum256(sig)

	g.mu.Lock()
	defer g.mu.Unlock()
	g.evictLocked(now)
	if _, dup := g.seen[key]; dup {
		return fmt.Errorf("%w: issued_at %s", errReplayed, issuedAt)
	}
	g.seen[key] = issued
	return nil
}

// evictLocked drops entries whose issuance can no longer be admitted on window
// grounds. Such an entry protects nothing — the window check already refuses a
// re-presentation of it — so retaining it would grow the map without bound on a
// long-running Control.
func (g *replayGuard) evictLocked(now time.Time) {
	for k, issued := range g.seen {
		if now.Sub(issued) > g.window {
			delete(g.seen, k)
		}
	}
}

// size reports how many issuances are remembered. It exists for the bound test:
// a cache that never forgets passes every functional assertion while leaking.
func (g *replayGuard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
