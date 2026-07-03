// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestRevokerRevokeByEgressBinding asserts the monotonic jti index records a
// mint against its session key (via BindKey) and revokes by the EgressBinding
// the below-seam finalizer step-1 already holds — keyed on the SAME BindKey off
// EgressBinding.Name (the host-derived session identity), NOT FilesystemID.
// record-key ≡ lookup-key by construction. The mark is permanent: a wall-clock
// setback after a revoke never reports the jti live again.
func TestRevokerRevokeByEgressBinding(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clk := state.NewFakeClock(testStart)
	r := cred.NewRevoker(clk)

	const sessionKey = "row-key-session-9"
	const jti = "jti-abc"

	if r.IsRevoked(jti) {
		t.Fatal("fresh jti must not be revoked")
	}

	// Record at mint under the session key, then revoke keyed off the
	// EgressBinding.Name (the same host-derived session identity). BindKey unifies
	// the two so the lookup cannot drift from the record.
	r.Record(sessionKey, jti)
	bind := runtime.EgressBinding{Name: runtime.SessionName(sessionKey)}
	outcome, err := r.Revoke(ctx, bind)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if outcome != runtime.RevokeMarkedDead {
		t.Fatalf("first revoke outcome = %v, want RevokeMarkedDead", outcome)
	}
	if !r.IsRevoked(jti) {
		t.Fatal("jti must be revoked after Revoke")
	}

	// Idempotent: a finalizer re-run revokes an already-dead jti without error and
	// reports the already_dead outcome.
	outcome, err = r.Revoke(ctx, bind)
	if err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if outcome != runtime.RevokeAlreadyDead {
		t.Fatalf("re-run outcome = %v, want RevokeAlreadyDead", outcome)
	}
	if !r.IsRevoked(jti) {
		t.Fatal("jti must stay revoked after a re-run")
	}

	// Permanent under a wall-clock setback far into the past.
	clk.SetWallClock(testStart.Add(-10000 * time.Hour))
	if !r.IsRevoked(jti) {
		t.Fatal("a wall-clock setback must never un-revoke a dead jti")
	}
	// And under a forward jump.
	clk.Advance(100000 * time.Hour)
	if !r.IsRevoked(jti) {
		t.Fatal("elapsed time must never un-revoke a dead jti")
	}
}

// TestRevokerUnboundSession asserts a revoke for a session whose bind-key was
// never recorded returns (RevokeNoneBound, ErrRevokeUnbound) — the finalizer
// treats it as a satisfied no-op but records none_bound as evidence — and that an
// empty Record is ignored.
func TestRevokerUnboundSession(t *testing.T) {
	t.Parallel()
	r := cred.NewRevoker(state.NewFakeClock(testStart))
	outcome, err := r.Revoke(context.Background(), runtime.EgressBinding{Name: runtime.SessionName("never-recorded")})
	if !errors.Is(err, cred.ErrRevokeUnbound) {
		t.Fatalf("unbound revoke: want ErrRevokeUnbound, got %v", err)
	}
	if outcome != runtime.RevokeNoneBound {
		t.Fatalf("unbound outcome = %v, want RevokeNoneBound", outcome)
	}

	// Empty inputs to Record bind nothing.
	r.Record("", "jti")
	r.Record("session", "")
	if _, err := r.Revoke(context.Background(), runtime.EgressBinding{Name: runtime.SessionName("session")}); !errors.Is(err, cred.ErrRevokeUnbound) {
		t.Fatalf("after ignored empty Record: want ErrRevokeUnbound, got %v", err)
	}
}

// TestRevokerRebindNewestMint asserts a second mint for the same session key
// supersedes the binding, so a teardown revokes the freshest jti.
func TestRevokerRebindNewestMint(t *testing.T) {
	t.Parallel()
	r := cred.NewRevoker(state.NewFakeClock(testStart))
	const sessionKey = "session-rebind"
	r.Record(sessionKey, "jti-old")
	r.Record(sessionKey, "jti-new")
	outcome, err := r.Revoke(context.Background(), runtime.EgressBinding{Name: runtime.SessionName(sessionKey)})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if outcome != runtime.RevokeMarkedDead {
		t.Fatalf("rebind revoke outcome = %v, want RevokeMarkedDead", outcome)
	}
	if !r.IsRevoked("jti-new") {
		t.Fatal("the newest jti must be revoked")
	}
	if r.IsRevoked("jti-old") {
		t.Fatal("the superseded jti was never marked dead by this revoke")
	}
}

// TestBindKeyUnifiesRecordAndRevoke is the DRIFT-KILLING pin: it drives the real
// composition (Record under a session key, Revoke off EgressBinding.Name) and
// asserts the revoke lands. It pins BindKey specifically — the record side and
// the lookup side must route through the SAME derivation. If a future change
// swaps either side to key on FilesystemID (or any other value), the record-key
// and lookup-key diverge and this test goes red with a none_bound outcome. It
// deliberately sets a DIFFERENT FilesystemID on the binding to prove the lookup
// does NOT depend on it.
func TestBindKeyUnifiesRecordAndRevoke(t *testing.T) {
	t.Parallel()
	r := cred.NewRevoker(state.NewFakeClock(testStart))
	const sessionKey = "row-key-unify"
	const jti = "jti-unify"
	r.Record(sessionKey, jti)

	// The binding carries a FilesystemID that is NOT the session key. If the
	// lookup keyed on FilesystemID (the pre-fix drift), it would miss.
	bind := runtime.EgressBinding{
		Name:         runtime.SessionName(sessionKey),
		FilesystemID: "some-unrelated-fs-id",
	}
	outcome, err := r.Revoke(context.Background(), bind)
	if err != nil {
		t.Fatalf("revoke via BindKey(Name): unexpected error %v (a drift to FilesystemID keying would return ErrRevokeUnbound)", err)
	}
	if outcome != runtime.RevokeMarkedDead {
		t.Fatalf("outcome = %v, want RevokeMarkedDead (the record and lookup keys must agree by construction)", outcome)
	}
	if !r.IsRevoked(jti) {
		t.Fatal("jti recorded under the session key must be revoked when looked up under the same BindKey")
	}
}
