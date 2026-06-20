// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package admission_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
)

// TestWorkloadProfileString pins the stable label of every WorkloadProfile enum
// value plus the fail-visible out-of-range label, so a forgotten arm renders as
// "workload_profile_unknown" in the audit record rather than mislabelling.
func TestWorkloadProfileString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		p    admission.WorkloadProfile
		want string
	}{
		{admission.ProfileTrustedOperator, "trusted_operator"},
		{admission.ProfileInternalWorkforce, "internal_workforce"},
		{admission.ProfileUntrusted, "untrusted"},
		{admission.WorkloadProfile(200), "workload_profile_unknown"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("WorkloadProfile(%d).String() = %q, want %q", c.p, got, c.want)
		}
	}
}

// TestRejectReasonString pins the stable label of every RejectReason enum value
// plus the fail-visible out-of-range label.
func TestRejectReasonString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		r    admission.RejectReason
		want string
	}{
		{admission.ReasonNone, "admitted"},
		{admission.ReasonPairingRejected, "profile may not run on this tier"},
		{admission.ReasonMicroVMNotShipped, "microVM tier not in v1 GA"},
		{admission.ReasonUnknownCell, "unknown profile or tier (fail-closed)"},
		{admission.RejectReason(200), "reject_reason_unknown"},
	}
	for _, c := range cases {
		if got := c.r.String(); got != c.want {
			t.Errorf("RejectReason(%d).String() = %q, want %q", c.r, got, c.want)
		}
	}
}

// TestRejectedErrorMessageAndUnwrap proves RejectedError renders its classifying
// reason in operator-facing text and unwraps to the matchable sentinel, so a caller
// can both display the reason and branch with errors.Is.
func TestRejectedErrorMessageAndUnwrap(t *testing.T) {
	t.Parallel()
	err := admission.RejectedError{Reason: admission.ReasonPairingRejected}

	msg := err.Error()
	if msg == "" {
		t.Fatal("RejectedError.Error() is empty; want operator-facing text")
	}
	if !strings.Contains(msg, admission.ReasonPairingRejected.String()) {
		t.Fatalf("RejectedError.Error() = %q; want it to carry the reason label %q", msg, admission.ReasonPairingRejected.String())
	}
	if !errors.Is(err, admission.ErrAdmissionRejected) {
		t.Fatalf("errors.Is(RejectedError, ErrAdmissionRejected) = false; want the sentinel to match")
	}
}
