// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package admission_test

import (
	"errors"
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// allProfiles and allTiers are the in-range enum values the table covers.
var (
	allProfiles = []admission.WorkloadProfile{
		admission.ProfileTrustedOperator,
		admission.ProfileInternalWorkforce,
		admission.ProfileUntrusted,
	}
	allTiers = []runtime.RuntimeTier{
		runtime.TierRunc,
		runtime.TierGvisor,
		runtime.TierFirecracker,
	}
)

// sharedKernelTiers are the tiers whose isolation is a shared-kernel boundary;
// the untrusted-never-on-shared-kernel property forbids an admit on either.
var sharedKernelTiers = []runtime.RuntimeTier{runtime.TierRunc, runtime.TierGvisor}

// TestDecideMatrixCells pins every one of the nine in-range cells to the
// documented Decision: the three admit cells and the six rejects (three
// pairing-rejected, three microVM-not-shipped).
func TestDecideMatrixCells(t *testing.T) {
	t.Parallel()
	cases := []struct {
		profile admission.WorkloadProfile
		tier    runtime.RuntimeTier
		want    admission.Decision
	}{
		// The three v1-GA admit cells.
		{admission.ProfileTrustedOperator, runtime.TierRunc, admission.Decision{Admitted: true, Reason: admission.ReasonNone}},
		{admission.ProfileTrustedOperator, runtime.TierGvisor, admission.Decision{Admitted: true, Reason: admission.ReasonNone}},
		{admission.ProfileInternalWorkforce, runtime.TierGvisor, admission.Decision{Admitted: true, Reason: admission.ReasonNone}},
		// Pairing-rejected: profile too low for the tier.
		{admission.ProfileInternalWorkforce, runtime.TierRunc, admission.Decision{Admitted: false, Reason: admission.ReasonPairingRejected}},
		{admission.ProfileUntrusted, runtime.TierRunc, admission.Decision{Admitted: false, Reason: admission.ReasonPairingRejected}},
		{admission.ProfileUntrusted, runtime.TierGvisor, admission.Decision{Admitted: false, Reason: admission.ReasonPairingRejected}},
		// microVM-not-shipped: firecracker column, every profile.
		{admission.ProfileTrustedOperator, runtime.TierFirecracker, admission.Decision{Admitted: false, Reason: admission.ReasonMicroVMNotShipped}},
		{admission.ProfileInternalWorkforce, runtime.TierFirecracker, admission.Decision{Admitted: false, Reason: admission.ReasonMicroVMNotShipped}},
		{admission.ProfileUntrusted, runtime.TierFirecracker, admission.Decision{Admitted: false, Reason: admission.ReasonMicroVMNotShipped}},
	}
	for _, c := range cases {
		got := admission.Decide(c.profile, c.tier)
		if got != c.want {
			t.Fatalf("Decide(%s, tier=%d) = %+v, want %+v", c.profile, c.tier, got, c.want)
		}
	}
}

// TestRejectedErrorWrapsSentinel proves the typed error carries the reason and
// still matches the sentinel, so the lifecycle can recover the classification
// while branching on errors.Is.
func TestRejectedErrorWrapsSentinel(t *testing.T) {
	t.Parallel()
	err := admission.RejectedError{Reason: admission.ReasonMicroVMNotShipped}
	if !errors.Is(err, admission.ErrAdmissionRejected) {
		t.Fatalf("RejectedError does not match ErrAdmissionRejected sentinel")
	}
	var re admission.RejectedError
	if !errors.As(err, &re) {
		t.Fatalf("errors.As failed to recover RejectedError")
	}
	if re.Reason != admission.ReasonMicroVMNotShipped {
		t.Fatalf("recovered reason = %v, want ReasonMicroVMNotShipped", re.Reason)
	}
}

// TestPropertyTotality is the mandatory NFR-named property: over the FULL uint8
// input space for both profile and tier, Decide never panics and returns a
// well-formed Decision (an admit has ReasonNone; a reject has a non-None reason).
// Out-of-range values must take the fail-closed ReasonUnknownCell arm.
func TestPropertyTotality(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		p := admission.WorkloadProfile(rapid.Uint8().Draw(rt, "profile"))
		tier := runtime.RuntimeTier(rapid.Uint8().Draw(rt, "tier"))

		d := admission.Decide(p, tier) // must not panic for any input

		if d.Admitted && d.Reason != admission.ReasonNone {
			rt.Fatalf("admitted decision carries non-None reason %v (profile=%d tier=%d)", d.Reason, p, tier)
		}
		if !d.Admitted && d.Reason == admission.ReasonNone {
			rt.Fatalf("rejected decision carries ReasonNone (profile=%d tier=%d)", p, tier)
		}
		inRange := p < 3 && tier < 3
		if !inRange && d.Admitted {
			rt.Fatalf("out-of-range enum admitted (profile=%d tier=%d)", p, tier)
		}
		if !inRange && d.Reason != admission.ReasonUnknownCell {
			rt.Fatalf("out-of-range enum did not take fail-closed default: reason=%v (profile=%d tier=%d)", d.Reason, p, tier)
		}
	})
}

// TestPropertyExactlyThreeAdmit proves exactly three of the nine in-range cells
// admit, and that the full out-of-range space adds none.
func TestPropertyExactlyThreeAdmit(t *testing.T) {
	t.Parallel()
	admitted := 0
	for _, p := range allProfiles {
		for _, tier := range allTiers {
			if admission.Decide(p, tier).Admitted {
				admitted++
			}
		}
	}
	if admitted != 3 {
		t.Fatalf("in-range admit count = %d, want exactly 3", admitted)
	}

	// A sweep of the full space must not raise the count above three.
	rapid.Check(t, func(rt *rapid.T) {
		p := admission.WorkloadProfile(rapid.Uint8().Draw(rt, "profile"))
		tier := runtime.RuntimeTier(rapid.Uint8().Draw(rt, "tier"))
		if admission.Decide(p, tier).Admitted && (p >= 3 || tier >= 3) {
			rt.Fatalf("an out-of-range pairing admitted (profile=%d tier=%d)", p, tier)
		}
	})
}

// TestPropertyUntrustedNeverSharedKernel proves the untrusted profile is never
// admitted on a shared-kernel tier (runc or gVisor) — the security invariant the
// matrix exists to enforce.
func TestPropertyUntrustedNeverSharedKernel(t *testing.T) {
	t.Parallel()
	for _, tier := range sharedKernelTiers {
		if admission.Decide(admission.ProfileUntrusted, tier).Admitted {
			t.Fatalf("untrusted admitted on shared-kernel tier %d", tier)
		}
	}
}

// TestPropertyFirecrackerColumnNeverAdmits proves no profile is admitted on the
// firecracker tier in v1 — the microVM column is uniformly not-shipped.
func TestPropertyFirecrackerColumnNeverAdmits(t *testing.T) {
	t.Parallel()
	for _, p := range allProfiles {
		d := admission.Decide(p, runtime.TierFirecracker)
		if d.Admitted {
			t.Fatalf("profile %s admitted on firecracker tier in v1", p)
		}
		if d.Reason != admission.ReasonMicroVMNotShipped {
			t.Fatalf("profile %s on firecracker: reason = %v, want ReasonMicroVMNotShipped", p, d.Reason)
		}
	}
}
