// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import (
	"crypto"
	"sync"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

const (
	// maxKeyAge is the rotation horizon: a signing key older than this should be
	// rotated out (operator/boot-driven in v1; the seam is present and tested,
	// there is no self-timer). It is the coarse wall-clock layer, kept distinct
	// from the monotonic liveness Revoker.
	maxKeyAge = 90 * 24 * time.Hour
	// overlapWindow is how long a just-superseded key keeps publishing its public
	// half after a Rotate, so a token minted just before the swap still validates
	// against the JWKS during the cutover.
	overlapWindow = 24 * time.Hour
)

// signingKey is one keyset entry: a kid, the private signer, its Alg, and the
// monotonic mark at activation. Age and overlap decisions read clk.Since
// against bornMark, so a wall-clock setback neither defers nor advances a
// rotation — the rotation horizon rides the monotonic timeline, not the
// settable wall clock.
type signingKey struct {
	kid      string
	alg      Alg
	priv     crypto.Signer // ed25519.PrivateKey or *ecdsa.PrivateKey
	pub      crypto.PublicKey
	bornMark time.Time // a clk.Now() reading; only compared via clk.Since
}

// PublicKey is the export shape the JWKS renderer consumes: the public half
// plus the alg it was signed under and the kid that matches the minted tokens.
// It carries NO private material.
type PublicKey struct {
	KID string
	Alg Alg
	Pub crypto.PublicKey // ed25519.PublicKey or *ecdsa.PublicKey
}

// KeySet holds the active signing key plus, during the overlap window, the
// just-superseded previous key. Reads take the RLock; Rotate swaps under the
// write Lock. Every age decision reads the injected monotonic Clock via
// clk.Since(bornMark), so the rotation horizon is immune to a wall-clock
// setback (NFR-SEC-48). KeySet is safe for concurrent use.
type KeySet struct {
	mu       sync.RWMutex
	clk      state.Clock
	active   signingKey
	previous *signingKey // non-nil only inside the overlap window
}

// newKeySet builds a KeySet with one active key. It is unexported; only the
// Signer constructs a KeySet, from the key it loaded off the mount.
func newKeySet(clk state.Clock, active signingKey) *KeySet {
	return &KeySet{clk: clk, active: active}
}

// mintKey returns the NEWEST key the mint signs with: always the active key.
// The previous key, during its overlap, only verifies (its public half is
// published); it never mints, so a rotation strictly advances the signing key.
func (ks *KeySet) mintKey() signingKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.active
}

// PublicKeys returns the public halves currently valid for verification: the
// active key always, plus the previous key while clk.Since(previous.bornMark)
// is within the overlap window. The JWKS publishes exactly this set, so a token
// minted just before a rotation still validates in the overlap, and the
// previous key drops out the moment the monotonic clock passes the window — a
// wall-clock setback never resurrects it because Since reads the monotonic
// base.
func (ks *KeySet) PublicKeys() []PublicKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]PublicKey, 0, 2)
	out = append(out, PublicKey{KID: ks.active.kid, Alg: ks.active.alg, Pub: ks.active.pub})
	if ks.previous != nil && ks.clk.Since(ks.previous.bornMark) <= overlapWindow {
		out = append(out, PublicKey{KID: ks.previous.kid, Alg: ks.previous.alg, Pub: ks.previous.pub})
	}
	return out
}

// activeAge reports the monotonic age of the active key, the value an operator
// compares against maxKeyAge to decide a rotation. v1 has no self-timer; this
// is the seam the boot/operator path reads.
func (ks *KeySet) activeAge() time.Duration {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.clk.Since(ks.active.bornMark)
}

// NeedsRotation reports whether the active key has reached the rotation horizon
// (its monotonic age is at or past maxKeyAge). It is the operator/boot-driven
// rotation seam: v1 has no background scheduler, so a caller polls this and calls
// Rotate. Because activeAge reads clk.Since against the monotonic base, a
// wall-clock setback neither defers nor forces a rotation (NFR-SEC-48).
func (ks *KeySet) NeedsRotation() bool {
	return ks.activeAge() >= maxKeyAge
}

// Rotate installs newActive as the signing key and demotes the current active
// to previous for the overlap window. It stamps the new key's bornMark from the
// injected Clock so the overlap and the rotation horizon both ride the
// monotonic timeline. Rotate is operator/boot-driven in v1 (no background
// scheduler); the seam is present and tested.
func (ks *KeySet) Rotate(newActive crypto.Signer, alg Alg, kid string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	demoted := ks.active
	ks.previous = &demoted
	ks.active = signingKey{
		kid:      kid,
		alg:      alg,
		priv:     newActive,
		pub:      newActive.Public(),
		bornMark: ks.clk.Now(),
	}
}
