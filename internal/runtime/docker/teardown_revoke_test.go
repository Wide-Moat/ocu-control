// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// revokeStart anchors the FakeClock the Revoker stamps its monotonic dead marks
// from, so the wall-setback assertion is reproducible.
var revokeStart = time.Date(2025, time.April, 1, 0, 0, 0, 0, time.UTC)

// TestTeardownStep1RevokesRecordedJTI proves the canon-fixed finalizer step-1 wires
// the real revoke: a jti the create-path mint recorded against the host-derived
// session key is marked dead when the finalizer runs with the Sandbox carrying that
// key on Egress.Name (the host-derived session identity, the BindKey both the mint
// record and this revoke route through). The revoke is keyed off the EgressBinding
// the step already holds — never a body hint, never FilesystemID — and the dead
// mark is monotonic.
func TestTeardownStep1RevokesRecordedJTI(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(revokeStart)
	revoker := cred.NewRevoker(clk)

	const sessionKey = "host-derived-session-key"
	const jti = "minted-jti-handle"
	revoker.Record(sessionKey, jti)
	if revoker.IsRevoked(jti) {
		t.Fatal("freshly recorded jti must not be revoked before teardown")
	}

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, Revoker: revoker})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}

	// The teardown Sandbox carries the host-derived session key on Egress.Name,
	// exactly as lifecycle.Destroy builds it (Name: SessionName(row.Key)), so
	// step-1 finds the recorded jti via BindKey. FilesystemID is a DIFFERENT value
	// (the mount scope) to prove the revoke does not key on it.
	sess := runtime.Sandbox{
		Name:      runtime.SessionName(sessionKey),
		RuntimeID: "ctr-revoke",
		Egress:    runtime.EgressBinding{Name: runtime.SessionName(sessionKey), FilesystemID: "some-mount-fs-id"},
		Tier:      runtime.TierRunc,
	}
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill: %v", err)
	}
	if !revoker.IsRevoked(jti) {
		t.Fatal("after the finalizer ran, the recorded jti must be revoked (step-1 real revoke)")
	}

	// A wall-clock setback after the revoke never un-revokes it (NFR-SEC-48).
	clk.SetWallClock(revokeStart.Add(-72 * time.Hour))
	if !revoker.IsRevoked(jti) {
		t.Fatal("a wall-clock setback must never un-revoke a dead jti")
	}

	// The finalizer is idempotent: a re-run revokes the already-dead jti without
	// error.
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("idempotent ForceKill re-run: %v", err)
	}
}

// TestTeardownStep1UnrecordedJTIIsSatisfiedNoOp proves an EgressBinding whose mint
// was never recorded (cred.ErrRevokeUnbound) is a satisfied no-op for the
// finalizer, not a teardown error: there is nothing live to revoke.
func TestTeardownStep1UnrecordedJTIIsSatisfiedNoOp(t *testing.T) {
	t.Parallel()
	revoker := cred.NewRevoker(state.NewFakeClock(revokeStart))

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, Revoker: revoker})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      runtime.SessionName("sess-unbound"),
		RuntimeID: "ctr-unbound",
		Egress:    runtime.EgressBinding{Name: runtime.SessionName("sess-unbound"), FilesystemID: "never-recorded"},
		Tier:      runtime.TierRunc,
	}
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill with an unrecorded jti must be a satisfied no-op, got: %v", err)
	}
}
