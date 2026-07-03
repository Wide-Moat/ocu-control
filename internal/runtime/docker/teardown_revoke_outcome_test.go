// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// recordingRevokeAuditor is a test double for the RevokeAuditor seam: it records
// every outcome the finalizer step-1 surfaces, so a test can prove the seam is
// actually driven end-to-end through a real Teardown rather than only asserted in
// isolation. It lives in the docker package (which does not import internal/audit)
// so the seam contract is exercised on its own terms, no audit dependency.
type recordingRevokeAuditor struct {
	binds    []runtime.EgressBinding
	outcomes []runtime.RevokeOutcome
}

func (r *recordingRevokeAuditor) RecordRevokeOutcome(_ context.Context, sess runtime.EgressBinding, outcome runtime.RevokeOutcome) {
	r.binds = append(r.binds, sess)
	r.outcomes = append(r.outcomes, outcome)
}

// TestTeardownStep1DrivesRevokeAuditorWithOutcome proves the wired RevokeAuditor is
// actually called by a REAL Teardown with the observed step-1 outcome — the
// coverage the isolated adapter test cannot give, because it drives the seam
// through NewDockerProvider(Deps{RevokeAuditor: ...}) and a real ForceKill, exactly
// as providerOf wires it in production. A live jti marked dead surfaces
// RevokeMarkedDead; an idempotent re-run surfaces RevokeAlreadyDead. If Deps did
// not carry the auditor to the finalizer (the boot-wiring drop), no outcome is
// recorded and this test goes RED.
func TestTeardownStep1DrivesRevokeAuditorWithOutcome(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(revokeStart)
	revoker := cred.NewRevoker(clk)

	const sessionKey = "auditor-wired-session-key"
	const jti = "auditor-wired-jti"
	revoker.Record(sessionKey, jti)

	auditor := &recordingRevokeAuditor{}
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, Revoker: revoker, RevokeAuditor: auditor})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}

	sess := runtime.Sandbox{
		Name:      runtime.SessionName(sessionKey),
		RuntimeID: "ctr-auditor",
		Egress:    runtime.EgressBinding{Name: runtime.SessionName(sessionKey), FilesystemID: "mount-fs-auditor"},
		Tier:      runtime.TierRunc,
	}

	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill: %v", err)
	}
	if len(auditor.outcomes) != 1 {
		t.Fatalf("after teardown the RevokeAuditor recorded %d outcomes, want exactly 1 (the seam is not driven end-to-end)", len(auditor.outcomes))
	}
	if auditor.outcomes[0] != runtime.RevokeMarkedDead {
		t.Errorf("first teardown outcome = %v, want RevokeMarkedDead (a live jti marked dead)", auditor.outcomes[0])
	}
	if auditor.binds[0].Name != runtime.SessionName(sessionKey) {
		t.Errorf("recorded bind Name = %q, want the session key %q", auditor.binds[0].Name, sessionKey)
	}

	// An idempotent re-run surfaces the already-dead outcome — still recorded, so
	// the anomaly-vs-normal distinction the evidence carries is preserved.
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("idempotent ForceKill re-run: %v", err)
	}
	if len(auditor.outcomes) != 2 {
		t.Fatalf("after the re-run the auditor recorded %d outcomes, want 2", len(auditor.outcomes))
	}
	if auditor.outcomes[1] != runtime.RevokeAlreadyDead {
		t.Errorf("re-run outcome = %v, want RevokeAlreadyDead (idempotent re-revoke)", auditor.outcomes[1])
	}
}

// TestTeardownStep1UnboundSurfacesNoneBound proves the anomaly path: a session whose
// mint was never recorded surfaces RevokeNoneBound to the auditor (a satisfied no-op
// for the finalizer error, but a DISTINCT recorded outcome, never dissolved into a
// blanket success). This is the evidence that makes a never-bound live destroy
// visible in the spine rather than silent.
func TestTeardownStep1UnboundSurfacesNoneBound(t *testing.T) {
	t.Parallel()
	revoker := cred.NewRevoker(state.NewFakeClock(revokeStart))

	auditor := &recordingRevokeAuditor{}
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, Revoker: revoker, RevokeAuditor: auditor})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      runtime.SessionName("never-minted"),
		RuntimeID: "ctr-none",
		Egress:    runtime.EgressBinding{Name: runtime.SessionName("never-minted"), FilesystemID: "unbound-fs"},
		Tier:      runtime.TierRunc,
	}
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill: %v", err)
	}
	if len(auditor.outcomes) != 1 {
		t.Fatalf("auditor recorded %d outcomes, want 1", len(auditor.outcomes))
	}
	if auditor.outcomes[0] != runtime.RevokeNoneBound {
		t.Errorf("unbound teardown outcome = %v, want RevokeNoneBound (the anomaly is recorded, not skipped)", auditor.outcomes[0])
	}
}
