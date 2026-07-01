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
// mint against its FilesystemID and revokes by the EgressBinding the below-seam
// finalizer step-1 already holds — without the session row carrying the jti. The
// mark is permanent: a wall-clock setback after a revoke never reports the jti
// live again.
func TestRevokerRevokeByEgressBinding(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clk := state.NewFakeClock(testStart)
	r := cred.NewRevoker(clk)

	const fsID = "fs-session-9"
	const jti = "jti-abc"

	if r.IsRevoked(jti) {
		t.Fatal("fresh jti must not be revoked")
	}

	// Record at mint, then revoke keyed off the EgressBinding (FilesystemID).
	r.Record(fsID, jti)
	bind := runtime.EgressBinding{FilesystemID: fsID}
	if err := r.Revoke(ctx, bind); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !r.IsRevoked(jti) {
		t.Fatal("jti must be revoked after Revoke")
	}

	// Idempotent: a finalizer re-run revokes an already-dead jti without error.
	if err := r.Revoke(ctx, bind); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
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

// TestRevokerUnboundFilesystemID asserts a revoke for a FilesystemID that was
// never recorded returns ErrRevokeUnbound (the finalizer treats it as a
// satisfied no-op), and that an empty Record is ignored.
func TestRevokerUnboundFilesystemID(t *testing.T) {
	t.Parallel()
	r := cred.NewRevoker(state.NewFakeClock(testStart))
	err := r.Revoke(context.Background(), runtime.EgressBinding{FilesystemID: "never-recorded"})
	if !errors.Is(err, cred.ErrRevokeUnbound) {
		t.Fatalf("unbound revoke: want ErrRevokeUnbound, got %v", err)
	}

	// Empty inputs to Record bind nothing.
	r.Record("", "jti")
	r.Record("fs", "")
	if err := r.Revoke(context.Background(), runtime.EgressBinding{FilesystemID: "fs"}); !errors.Is(err, cred.ErrRevokeUnbound) {
		t.Fatalf("after ignored empty Record: want ErrRevokeUnbound, got %v", err)
	}
}

// TestRevokerRebindNewestMint asserts a second mint for the same FilesystemID
// supersedes the binding, so a teardown revokes the freshest jti.
func TestRevokerRebindNewestMint(t *testing.T) {
	t.Parallel()
	r := cred.NewRevoker(state.NewFakeClock(testStart))
	const fsID = "fs-rebind"
	r.Record(fsID, "jti-old")
	r.Record(fsID, "jti-new")
	if err := r.Revoke(context.Background(), runtime.EgressBinding{FilesystemID: fsID}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !r.IsRevoked("jti-new") {
		t.Fatal("the newest jti must be revoked")
	}
	if r.IsRevoked("jti-old") {
		t.Fatal("the superseded jti was never marked dead by this revoke")
	}
}
