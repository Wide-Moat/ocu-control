// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestCreateHostStageFailureEmitsAuditWithStageName is the G-1 keystone. The
// pre-side-effect deny stages (admit/quota/reserve) already emit a create-rejection
// audit record, but the host-side stages that run AFTER durable state
// (handoff/mint/render/materialize/commit/bind) emitted nothing on failure: a
// refusal surfaced only as an opaque 409 with the failing stage named nowhere, which
// made a wedged host-side stage nearly impossible to diagnose from the audit trail.
//
// The fix has the create runner emit the SAME ActionCreateRejected (an OCSF consumer
// counts one "create rejected" class; the differentiator is the Reason, never a
// distinct Action) with Reason "stage-failed:<name>" for a host-side stage failure —
// only for stages that do not emit their own rejection, so the working
// admit/quota/reserve records are not doubled. This test fails materialize (a
// host-side stage) and asserts exactly one ActionCreateRejected carrying the failing
// stage name. Neuter the runner emit and no record is written — this reds.
func TestCreateHostStageFailureEmitsAuditWithStageName(t *testing.T) {
	t.Parallel()
	h := newRejectHarness(t, admission.ProfileTrustedOperator, runtime.TierRunc, generousLimits())
	// Fail materialize — a host-side stage that runs AFTER reserve, so no deny stage
	// emitted for it; before the fix nothing recorded the failure.
	h.provider.failMaterialize = true

	_, err := h.mgr.Create(context.Background(), input("stage-fail"))
	if !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("Create error = %v, want ErrMaterialize", err)
	}

	// Exactly one ActionCreateRejected (same Action as the deny stages), carrying the
	// host-attested identity and the failing stage name in the Reason.
	rec := onlyRejection(t, h.audit)
	if rec.Reason != "stage-failed:materialize" {
		t.Fatalf("rejection Reason = %q, want stage-failed:materialize", rec.Reason)
	}
	if rec.Key == "" {
		t.Fatal("host-side stage-fail audit has a blank correlation key")
	}
}

// TestCreateDenyStageDoesNotDoubleEmit guards the emitsOwnRejection flag: a deny
// stage (quota) that emits its OWN rejection must NOT also get a generic
// "stage-failed:*" record from the runner — exactly one record, carrying the deny
// stage's own specific cause, not the generic stage-fail one.
func TestCreateDenyStageDoesNotDoubleEmit(t *testing.T) {
	t.Parallel()
	// ConcurrentSessionsPerTenant=1: the first create succeeds, the second is refused
	// by the quota (a deny stage that emits its own quota-rejection).
	h := newRejectHarness(t, admission.ProfileTrustedOperator, runtime.TierRunc,
		quota.Limits{ConcurrentSessionsPerTenant: 1, CreateRatePerCallerPerMin: 100})
	ctx := context.Background()

	if _, err := h.mgr.Create(ctx, input("first")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := h.mgr.Create(ctx, input("second")); err == nil {
		t.Fatal("second Create over the concurrency limit must be refused")
	}

	// The sink holds the first create's commit plus exactly one rejection for the
	// second — and that rejection carries the quota deny's OWN cause, never a generic
	// runner stage-fail record (no double emit).
	recs := h.audit.Records()
	var rejections int
	var rejectReason string
	for _, r := range recs {
		if r.Action == recs[len(recs)-1].Action && r.Reason != "" && strings.Contains(r.Reason, "rejection") {
			rejections++
			rejectReason = r.Reason
		}
	}
	if rejections != 1 {
		t.Fatalf("audit holds %d rejection records, want exactly 1 (no double emit); records=%+v", rejections, recs)
	}
	if strings.HasPrefix(rejectReason, "stage-failed:") {
		t.Fatalf("deny stage got a generic runner stage-fail record (%q); it must keep its own specific cause", rejectReason)
	}
	if rejectReason != "quota-rejection" {
		t.Fatalf("quota deny Reason = %q, want quota-rejection (its own cause, not doubled)", rejectReason)
	}
}
