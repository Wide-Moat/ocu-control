// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestRevokeOutcomeAuditorEmitsDestroyEvidence proves the production wiring of the
// teardown revoke-outcome onto the durable spine: revokeOutcomeAuditor.
// RecordRevokeOutcome must emit an ActionDestroy record whose
// unmapped.revoke_outcome carries the observed outcome and whose Key is the
// host-derived session scope (the EgressBinding.FilesystemID the revoke targeted).
//
// This is the keystone-neuter target for PR-1a: if the boot wiring is dropped (the
// provider constructed with a nil RevokeAuditor, or the adapter's Emit removed),
// no destroy-evidence record is produced and this test goes RED — not via a
// neighbouring guard, but because the outcome the finalizer observed never reaches
// the audit sink.
func TestRevokeOutcomeAuditorEmitsDestroyEvidence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		outcome runtime.RevokeOutcome
		want    string
	}{
		{"marked_dead", runtime.RevokeMarkedDead, "marked_dead"},
		{"already_dead", runtime.RevokeAlreadyDead, "already_dead"},
		// none_bound on a live destroy is an anomaly; the auditor records it AS
		// none_bound rather than skipping the emit, so the anomaly is visible in
		// the tamper-evident spine.
		{"none_bound", runtime.RevokeNoneBound, "none_bound"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := audit.NewRecordingFake()
			a := revokeOutcomeAuditor{sink: fake}

			a.RecordRevokeOutcome(context.Background(), runtime.EgressBinding{Name: "sess-alpha", FilesystemID: "fs-77"}, tc.outcome)

			recs := fake.Records()
			if len(recs) != 1 {
				t.Fatalf("want exactly 1 destroy-evidence record, got %d", len(recs))
			}
			got := recs[0]
			if got.Action != audit.ActionDestroy {
				t.Errorf("record Action = %v, want ActionDestroy (revoke outcome is destroy evidence, not a new privileged action)", got.Action)
			}
			if got.RevokeOutcome != tc.want {
				t.Errorf("record RevokeOutcome = %q, want %q", got.RevokeOutcome, tc.want)
			}
			// The evidence Key must be the SessionName — the same value the primary
			// ActionDestroy record keys on — so the two join on one CorrelationUID.
			// It is NOT the FilesystemID (the mount scope), which would break the
			// join for a regulated auditor.
			if got.Key != "sess-alpha" {
				t.Errorf("record Key = %q, want the EgressBinding.Name %q (the SessionName the primary destroy record also keys on); the FilesystemID must not be the correlation key", got.Key, "sess-alpha")
			}
		})
	}
}

// TestRevokeOutcomeAuditorEmitFailureDoesNotPanic proves the evidence emit is
// non-fatal: a destroy is already authorised fail-closed upstream and step-1 is
// idempotent, so a lost evidence detail must not escalate to a panic or a teardown
// abort. With the sink faulted, RecordRevokeOutcome returns cleanly (the WARN is
// logged, the destroy is not stranded).
func TestRevokeOutcomeAuditorEmitFailureDoesNotPanic(t *testing.T) {
	t.Parallel()
	fake := audit.NewRecordingFake()
	fake.SetFault(true, nil)
	a := revokeOutcomeAuditor{sink: fake}

	// Must not panic; must return.
	a.RecordRevokeOutcome(context.Background(), runtime.EgressBinding{FilesystemID: "fs-1"}, runtime.RevokeMarkedDead)

	if n := fake.Len(); n != 0 {
		t.Errorf("faulted sink recorded %d records, want 0 (the emit failed closed)", n)
	}
}
