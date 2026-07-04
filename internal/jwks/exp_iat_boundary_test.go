// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/jwks"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestExpBoundaryIsExclusive pins the EXACT expiry edge through the real
// Verifier.Verify — the boundary the existing TestExpiredAfterAdvanceFails
// (which only checks exp + 1s) leaves unproven. The weak Storage-JWT is
// short-lived and exp is the single temporal gate, so the precise accept/reject
// instant is load-bearing: an off-by-one that made exp inclusive would extend
// every token's life by the verifier's clock granularity.
//
// The edge is EXCLUSIVE: a token is valid strictly before exp (now == exp-1s)
// and invalid at or after exp (now == exp). Slackening the exp check in
// verifier.go — e.g. adding a WithLeeway large enough to cover the boundary —
// makes the at-exp case verify and reds the second assertion.
func TestExpBoundaryIsExclusive(t *testing.T) {
	signer, clk := newSigner(t, cred.AlgEdDSA)
	tok := mintStorage(t, signer)
	set := publishFrom(t, signer)
	v := jwks.NewVerifier(set, clk.Now, nil)

	// One second before exp: still valid.
	clk.Advance(testStorageTTL - time.Second)
	if _, err := v.Verify(tok.Reveal()); err != nil {
		t.Fatalf("at exp-1s the token must still verify, got %v", err)
	}

	// Exactly at exp: invalid (the edge is exclusive — now < exp is the valid
	// window, now >= exp is expired).
	clk.Advance(time.Second)
	if _, err := v.Verify(tok.Reveal()); err == nil {
		t.Fatal("at exp the token must be expired (the exp edge is exclusive: valid iff now < exp)")
	} else if !errors.Is(err, jwks.ErrVerify) {
		t.Fatalf("at exp the error = %v, want ErrVerify", err)
	}
}

// TestIatIsInformationalNotGated documents an intentional minimal-shelf posture:
// the verifier gates on exp ONLY (WithExpirationRequired). iat is parsed into the
// claims for the trail but is NOT enforced as a not-before, so a token whose
// issued-at is in the FUTURE relative to the verifying clock still verifies.
//
// This is by design, not an oversight (architect ruling, fleet-consistent with
// the sandbox verifier): (1) the weak Storage-JWT is minted by Control itself,
// which never future-dates iat — a future iat could only come from a compromised
// minter, which would forge exp/scope too, so a not-before check buys nothing;
// (2) the token is short-lived and exp is strictly gated, closing the only real
// replay window; (3) a hand-rolled not-before diverging from the verify library
// is its own risk on the crypto path. If the canon ever introduces nbf, that is
// an issuer-side ADR applied symmetrically to every consumer, not a one-sided
// consumer patch.
//
// The test pins the intent so a future change that starts REJECTING a future iat
// (adding not-before enforcement) reds here and forces a deliberate decision
// rather than a silent posture drift.
func TestIatIsInformationalNotGated(t *testing.T) {
	// Mint at a LATER instant than the verifier's clock, so the token's iat is in
	// the future from the verifier's point of view.
	mintClk := state.NewFakeClock(testStart.Add(time.Hour))
	cfg := cred.Config{
		Alg:             cred.AlgEdDSA,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		ExecIssuer:      "https://control.example/exec-provisional",
		ExecAudience:    "guest.exec.provisional",
		StorageTTL:      testStorageTTL,
	}
	signer, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgEdDSA), mintClk, cfg)
	if err != nil {
		t.Fatalf("LoadSignerFromMount: %v", err)
	}
	tok := mintStorage(t, signer)
	set := publishFrom(t, signer)

	// The verifier runs an HOUR BEFORE the token was issued (iat is in its future),
	// but well within the token's validity window (mint+TTL is still ahead).
	verifyClk := state.NewFakeClock(testStart)
	v := jwks.NewVerifier(set, verifyClk.Now, nil)

	if _, err := v.Verify(tok.Reveal()); err != nil {
		t.Fatalf("a token with a future iat must still verify (iat is informational, not a not-before gate); got %v", err)
	}
}
