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
// The seam is the single OperatorSeam this operator adapter holds: only a holder
// of the seam can mint, so the mint path lives here, behind the verify, and
// nowhere a gateway-shaped caller could reach it.
func verifyThenMint(ctx context.Context, verifier killswitch.SOARVerifier, seam ingress.OperatorSeam, payload, sig []byte) (ingress.OperatorScope, error) {
	if verifier == nil {
		// No verifier wired: a SOAR webhook cannot be trusted, so it is refused
		// fail-closed exactly as an unverifiable signature would be.
		return ingress.OperatorScope{}, fmt.Errorf("%w: no SOAR verifier configured", killswitch.ErrSOARUnverified)
	}
	if err := verifier.Verify(ctx, payload, sig); err != nil {
		// Verify failed: no scope is minted, so the revoke cannot proceed. The typed
		// cause (expected to wrap ErrSOARUnverified) propagates for the caller's
		// refusal text and audit.
		return ingress.OperatorScope{}, fmt.Errorf("soar verify: %w", err)
	}
	// Verified: mint the operator scope from the held seam. The scope authorizes the
	// Engine call that follows; without the seam this line could not compile.
	return seam.Mint(), nil
}
