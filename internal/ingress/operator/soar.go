// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
)

// verifyThenMint is the SOAR trust gate (P2-R2): it runs the SOARVerifier over
// the webhook payload+signature and mints an ingress.OperatorScope ONLY on a
// successful verify. Because the scope is the required parameter of every
// kill-switch Engine method, an unverifiable SOAR call yields NO scope and thus
// cannot even FORM an Engine call — "acting" is structurally impossible before
// "verified". A verify failure returns killswitch.ErrSOARUnverified (the verifier
// is expected to wrap that sentinel) and the zero OperatorScope, which
// Engine.Valid would reject even if it somehow reached an Engine.
//
// The scope is minted with the SOAR PRINCIPAL identity Verify surfaced, NOT the
// unix-socket peer that delivered the webhook: for a SOAR-driven revoke the
// authority is the verified signer, so the downstream audit actor (actor.user)
// must be the principal (P2-R2 / NFR-SEC-43). The socket peer is still attested by
// the caller (the webhook must arrive on the operator socket), but it is not the
// actor of the revoke.
//
// The seam is the single OperatorSeam this operator adapter holds: only a holder
// of the seam can mint, so the mint path lives here, behind the verify, and
// nowhere a gateway-shaped caller could reach it.
// verifyThenAdmit runs the SOAR trust gate in the one order that is safe
// (ADR-0039): the signature is verified FIRST, and only a verified issuance is
// offered to the replay guard.
//
// The order is the whole point. If an unverified issuance could enter the seen
// set, anyone able to reach the operator socket would present a forged
// signature carrying a future-dated issued_at, poison the cache, and have the
// legitimate revoke that follows refused as a replay — a denial of service on
// the kill path, mounted without holding any key. So a refused verify leaves no
// trace, and the guard only ever remembers calls that were authentic.
//
// The window refusal is likewise decided after the signature check: deciding it
// first would let an unauthenticated caller probe the host's clock skew by
// reading which error came back.
func verifyThenAdmit(ctx context.Context, verifier killswitch.SOARVerifier, guard *replayGuard, issuedAt string, payload, sig []byte) error {
	if verifier == nil {
		return fmt.Errorf("%w: no SOAR verifier configured", killswitch.ErrSOARUnverified)
	}
	if _, err := verifier.Verify(ctx, payload, sig); err != nil {
		return fmt.Errorf("soar verify: %w", err)
	}
	if guard == nil {
		// No guard wired: a revoke would be replayable for the life of its
		// window, so it is refused rather than served without the protection the
		// contract's 409 promises.
		return fmt.Errorf("%w: no replay guard configured", killswitch.ErrSOARUnverified)
	}
	return guard.admit(issuedAt, sig)
}

func verifyThenMint(ctx context.Context, verifier killswitch.SOARVerifier, seam ingress.OperatorSeam, payload, sig []byte) (ingress.OperatorScope, error) {
	if verifier == nil {
		// No verifier wired: a SOAR webhook cannot be trusted, so it is refused
		// fail-closed exactly as an unverifiable signature would be.
		return ingress.OperatorScope{}, fmt.Errorf("%w: no SOAR verifier configured", killswitch.ErrSOARUnverified)
	}
	principal, err := verifier.Verify(ctx, payload, sig)
	if err != nil {
		// Verify failed: no scope is minted, so the revoke cannot proceed. The typed
		// cause (expected to wrap ErrSOARUnverified) propagates for the caller's
		// refusal text and audit.
		return ingress.OperatorScope{}, fmt.Errorf("soar verify: %w", err)
	}
	// Verified: mint the operator scope from the held seam, stamped with the SOAR
	// PRINCIPAL identity. The scope authorizes the Engine call that follows and
	// carries the principal as the audit actor; without the seam this line could not
	// compile.
	return seam.Mint(principal), nil
}
