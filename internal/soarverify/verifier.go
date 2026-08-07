// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package soarverify

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Principal is one entry of the host-owned keyring: a SOAR platform identity
// and the Ed25519 public key(s) that speak for it. The operator provisions
// these as configuration at deploy time; there is no network fetch, because a
// revoke must not acquire an availability dependency on a key endpoint
// (ADR-0039).
//
// Keys holds more than one entry only during a rotation overlap, so a SOAR
// platform can cut over without a window in which its revokes are refused.
type Principal struct {
	// Name is the audit actor recorded for a revoke this principal signs. It
	// becomes state.Identity.Caller, and it is CONFIG-derived: the body never
	// names the actor (NFR-SEC-43).
	Name string
	// Tenant is the tenant scope stamped on the minted OperatorScope.
	Tenant string
	// Keys are the Ed25519 public keys accepted for this principal.
	Keys []ed25519.PublicKey
}

// Verifier checks an Ed25519 SOAR webhook signature against a fixed keyring.
// It holds no state beyond that keyring: the issued_at window and the
// seen-signature cache belong to the operator adapter, so swapping this
// verifier for the full-shelf SVID one cannot drop replay protection.
type Verifier struct {
	principals []Principal
}

// New builds a Verifier over the supplied keyring, rejecting one that could
// never verify anything. Failing here rather than at the first revoke matters:
// an unusable keyring otherwise surfaces as a refused kill-switch call during
// the incident it was provisioned for.
func New(principals []Principal) (*Verifier, error) {
	if len(principals) == 0 {
		return nil, fmt.Errorf("soarverify: keyring is empty; no SOAR revoke could ever verify")
	}
	for i, p := range principals {
		if p.Name == "" {
			return nil, fmt.Errorf("soarverify: principal %d has no name; the name is the audit actor for every revoke it signs", i)
		}
		if len(p.Keys) == 0 {
			return nil, fmt.Errorf("soarverify: principal %q has no keys", p.Name)
		}
		for j, k := range p.Keys {
			if len(k) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("soarverify: principal %q key %d is %d bytes, want %d (ed25519)", p.Name, j, len(k), ed25519.PublicKeySize)
			}
		}
	}
	// Copy so a later mutation of the caller's slice cannot widen the keyring
	// of a running verifier.
	owned := make([]Principal, len(principals))
	copy(owned, principals)
	return &Verifier{principals: owned}, nil
}

// Verify reports the SOAR principal that signed payload, or ErrSOARUnverified.
//
// The frozen body carries no key-id, so the keyring is trial-verified: an
// in-band selector would be caller-influenced input on the path that decides
// whether a revoke is authentic. Ed25519 verification is cheap and the keyring
// is operator-sized, so trial verification costs nothing worth the surface.
//
// A refusal returns the ZERO Identity. The fence mints a scope from whatever
// this returns, so a non-zero identity alongside an error would be a mintable
// scope for an unverified caller.
func (v *Verifier) Verify(_ context.Context, payload, sig []byte) (state.Identity, error) {
	// A wrong-size signature is refused here purely so the operator log names
	// the shape problem. ed25519.Verify already returns false for any length
	// rather than panicking, so this guard buys DIAGNOSIS, not safety: without
	// it a malformed webhook is indistinguishable from a forged one, and the
	// two need different operator responses.
	if len(sig) != ed25519.SignatureSize {
		return state.Identity{}, fmt.Errorf("%w: signature is %d bytes, want %d",
			killswitch.ErrSOARUnverified, len(sig), ed25519.SignatureSize)
	}
	for _, p := range v.principals {
		for _, k := range p.Keys {
			if ed25519.Verify(k, payload, sig) {
				return state.Identity{Tenant: p.Tenant, Caller: p.Name}, nil
			}
		}
	}
	// The refusal names no principal and no key: an attacker learns only that
	// the call was refused, never which configured identity was probed.
	return state.Identity{}, fmt.Errorf("%w: no configured SOAR key verifies this signature",
		killswitch.ErrSOARUnverified)
}
