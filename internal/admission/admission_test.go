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

// TestDecideOutOfRangeBoundary is the DETERMINISTIC pin on Decide's fail-closed
// bounds check — the exact edge where a value first exceeds the 3×3 grid. It
// covers the first out-of-range profile (3) against every in-range tier, the
// first out-of-range tier (3) against every in-range profile, and the (3,3)
// corner. Every one of these must reject with ReasonUnknownCell and must not
// panic (a bare index into the 3×3 matrix at row/column 3 is out of range).
//
// TestPropertyTotality already asserts this property over the full uint8 space,
// but it reaches the exact boundary (profile==3 or tier==3, the only inputs that
// would index one past the matrix) only when its random Draw happens to land
// there — so an off-by-one in the bounds check (>= numTiers weakened to
// > numTiers, which lets tier==3 fall through to matrix[p][3]) survives on a run
// where the boundary is not drawn. This table hits every boundary cell on every
// run, so that off-by-one — and its symmetric profile twin — is killed
// deterministically. The rapid totality property is complementary and stays.
func TestDecideOutOfRangeBoundary(t *testing.T) {
	t.Parallel()

	// The first value one past the in-range grid for both axes. numProfiles and
	// numTiers are both 3, so 3 is the boundary that would index matrix[.][3]
	// (out of range) if the bounds check let it through.
	const firstOutOfRange = 3

	assertUnknownCell := func(t *testing.T, p admission.WorkloadProfile, tier runtime.RuntimeTier) {
		t.Helper()
		// A wrong bounds check indexes matrix at row/column 3 and panics; recover
		// turns that into a clear test failure rather than a crashed run.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Decide(profile=%d, tier=%d) panicked (bounds check let an out-of-range value index the matrix): %v", p, tier, r)
			}
		}()
		got := admission.Decide(p, tier)
		if got.Admitted {
			t.Fatalf("Decide(profile=%d, tier=%d) admitted an out-of-range value; want fail-closed reject", p, tier)
		}
		if got.Reason != admission.ReasonUnknownCell {
			t.Fatalf("Decide(profile=%d, tier=%d) = reason %v, want ReasonUnknownCell (fail-closed default)", p, tier, got.Reason)
		}
	}

	// The out-of-range TIER (3) against every in-range profile — the cell that a
	// weakened `tier >= numTiers` bounds check would let index matrix[p][3].
	for _, p := range allProfiles {
		assertUnknownCell(t, p, runtime.RuntimeTier(firstOutOfRange))
	}
	// The out-of-range PROFILE (3) against every in-range tier — the symmetric
	// cell a weakened `profile >= numProfiles` check would let index matrix[3][t].
	for _, tier := range allTiers {
		assertUnknownCell(t, admission.WorkloadProfile(firstOutOfRange), tier)
	}
	// The corner where both axes are out of range.
	assertUnknownCell(t, admission.WorkloadProfile(firstOutOfRange), runtime.RuntimeTier(firstOutOfRange))
}
