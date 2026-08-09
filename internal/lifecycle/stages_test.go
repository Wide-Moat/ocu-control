// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle

import (
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// An operator debugging a refused create is told by the ingress that the detail
// lives in the audit trail. It did not: the trail carried "stage-failed:<name>",
// which answers where and never why. A missing guest image and a full disk wrote
// the identical line, so the one artifact that knew the cause discarded it.
//
// These pin the reason CARRIES the cause and stays bounded, because the same
// record is what a caller could otherwise pad.
func TestStageFailureReasonCarriesTheCause(t *testing.T) {
	got := stageFailureReason("materialize", errors.New("no such image: ocu-guest:fleet"))
	if !strings.HasPrefix(got, "stage-failed:materialize") {
		t.Errorf("reason lost the stage name: %q", got)
	}
	if !strings.Contains(got, "no such image") {
		t.Errorf("reason names the stage but not the cause, which is the defect this "+
			"guards: %q", got)
	}
}

func TestStageFailureReasonIsBounded(t *testing.T) {
	got := stageFailureReason("materialize", errors.New(strings.Repeat("A", 5000)))
	if len(got) > reasonErrCap+64 {
		t.Errorf("reason is unbounded (%d bytes); a caller-influenced error would let "+
			"one create pad the operator's audit log", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("a truncated reason must say it was truncated, else a clipped cause "+
			"reads as the whole cause: %q", got)
	}
}

func TestStageFailureReasonNilErrDoesNotSilentlyRegress(t *testing.T) {
	// The runner never passes nil, but if it ever did, the reason would quietly
	// become the bare stage name again — the exact state this change removed.
	got := stageFailureReason("materialize", nil)
	if got != "stage-failed:materialize" {
		t.Errorf("nil-error reason should be the bare stage name, got %q", got)
	}
}

// TestQuotaRejectionReasonNamesTheRightDimension binds each label to the cause
// that produced it, not merely to "some label was set".
//
// Asserting only that the reason is no longer the flat "quota-rejection" leaves
// the swap undetected: with the create-rate and concurrent-sessions arms
// exchanged, every existing assertion still passes, and the operator is sent to
// the counter that will look healthy — which is the failure this change exists
// to remove, reproduced exactly. Mutation-testing found that hole; this closes
// it by pairing each sentinel with the label it must produce.
func TestQuotaRejectionReasonNamesTheRightDimension(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"create-rate window", quota.ErrCreateRateDimension, "quota-rejection:create-rate"},
		{"concurrent-session cap", quota.ErrConcurrentDimension, "quota-rejection:concurrent-sessions"},
		{"store unavailable is not a cap", state.ErrStoreUnavailable, "quota-rejection:store-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := quotaRejectionReason(tc.err); got != tc.want {
				t.Errorf("quotaRejectionReason(%v) = %q, want %q — an operator reading the wrong dimension checks a counter that looks healthy", tc.err, got, tc.want)
			}
		})
	}

	// The control: an error matching none of the three still yields the bare
	// label, so the pairs above cannot be satisfied by a function that appends a
	// suffix unconditionally.
	if got := quotaRejectionReason(errors.New("unrelated")); got != "quota-rejection" {
		t.Errorf("an unclassified error produced %q, want the bare label", got)
	}
}
