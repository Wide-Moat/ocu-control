// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// recordingVerifier reports whether Verify ran, so a test can prove the
// signature check happened BEFORE the cache was touched.
type recordingVerifier struct {
	called bool
	err    error
}

func (v *recordingVerifier) Verify(_ context.Context, _, _ []byte) (state.Identity, error) {
	v.called = true
	if v.err != nil {
		return state.Identity{}, v.err
	}
	return state.Identity{Tenant: "acme", Caller: "soar:test"}, nil
}

// TestUnverifiedIssuanceNeverEntersTheCache is the ordering invariant ADR-0039
// pins, and the reason the cache lives in the adapter rather than the verifier.
//
// If an unverified issuance were remembered, anyone who reaches the operator
// socket could present a forged signature carrying a future-dated issued_at,
// poison the cache, and have the LEGITIMATE revoke that follows refused as a
// replay — a denial of service on the kill path, mounted without any key.
func TestUnverifiedIssuanceNeverEntersTheCache(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	guard := newReplayGuard(clk, 300*time.Second)
	issued := rfc3339(replayStart)
	forged := []byte("attacker-signature")

	// The attacker's call: verification fails, so admit must never be reached.
	v := &recordingVerifier{err: killswitch.ErrSOARUnverified}
	if err := verifyThenAdmit(context.Background(), v, guard, issued, []byte("payload"), forged); err == nil {
		t.Fatal("an unverifiable call was admitted")
	}
	if !v.called {
		t.Error("Verify was not called; the guard must not run before the signature check")
	}
	if n := guard.size(); n != 0 {
		t.Fatalf("the cache holds %d entries after a REFUSED call — an attacker who "+
			"reaches the socket can poison it and block the real revoke", n)
	}

	// The legitimate holder now presents the same issuance and must be admitted.
	ok := &recordingVerifier{}
	if err := verifyThenAdmit(context.Background(), ok, guard, issued, []byte("payload"), forged); err != nil {
		t.Errorf("the legitimate revoke was refused after an earlier forged attempt: %v", err)
	}
}

// TestVerifiedIssuanceIsRememberedOnce pins the other half: a call that DOES
// verify is cached, so its own replay is refused.
func TestVerifiedIssuanceIsRememberedOnce(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	guard := newReplayGuard(clk, 300*time.Second)
	issued := rfc3339(replayStart)
	sig := []byte("good-signature")

	v := &recordingVerifier{}
	if err := verifyThenAdmit(context.Background(), v, guard, issued, []byte("payload"), sig); err != nil {
		t.Fatalf("first presentation refused: %v", err)
	}
	err := verifyThenAdmit(context.Background(), v, guard, issued, []byte("payload"), sig)
	if !errors.Is(err, errReplayed) {
		t.Errorf("re-presenting a verified revoke gave %v, want errReplayed — a "+
			"captured call must not act twice", err)
	}
}

// TestUnwiredSeamsRefuseRatherThanServe covers the two fail-open holes. Neither
// seam being wired is a configuration state a deployment can reach, so each must
// refuse: a nil verifier would let ANY caller revoke, and a nil guard would
// serve a revoke that is replayable for the life of its window while the
// contract promises a 409.
func TestUnwiredSeamsRefuseRatherThanServe(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	guard := newReplayGuard(clk, 300*time.Second)
	issued := rfc3339(replayStart)

	t.Run("nil verifier", func(t *testing.T) {
		err := verifyThenAdmit(context.Background(), nil, guard, issued, []byte("p"), []byte("s"))
		if err == nil {
			t.Fatal("a revoke was served with NO verifier wired — any caller reaching " +
				"the operator socket could revoke")
		}
		if !errors.Is(err, killswitch.ErrSOARUnverified) {
			t.Errorf("error %v does not wrap ErrSOARUnverified; the 401 keys on it", err)
		}
	})

	t.Run("nil guard", func(t *testing.T) {
		v := &recordingVerifier{}
		err := verifyThenAdmit(context.Background(), v, nil, issued, []byte("p"), []byte("s"))
		if err == nil {
			t.Fatal("a revoke was served with NO replay guard wired — a captured call " +
				"could be re-presented for the life of its window")
		}
	})
}

// TestWindowRefusalStillRunsTheVerifierFirst keeps the two refusals ordered.
// Deciding the window before the signature would let an unauthenticated caller
// probe the host's clock skew by timing which error it gets back.
func TestWindowRefusalStillRunsTheVerifierFirst(t *testing.T) {
	clk := state.NewFakeClock(replayStart)
	guard := newReplayGuard(clk, 300*time.Second)
	stale := rfc3339(replayStart.Add(-10 * time.Minute))

	v := &recordingVerifier{}
	err := verifyThenAdmit(context.Background(), v, guard, stale, []byte("payload"), []byte("sig"))
	if !errors.Is(err, errOutsideWindow) {
		t.Fatalf("a stale issuance gave %v, want errOutsideWindow", err)
	}
	if !v.called {
		t.Error("the window was decided without verifying the signature; an " +
			"unauthenticated caller could probe host clock skew from the error alone")
	}
}
