// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package admission decides whether a deployment's declared workload profile may
// run on its configured isolation tier (NFR-SEC-38). The decision is a TOTAL,
// PURE lookup over a 3×3 data table indexed by (WorkloadProfile, RuntimeTier):
// every in-range pairing maps to exactly one Decision, and any unknown enum value
// REJECTS with ReasonUnknownCell. The default is fail-closed — a new tier or
// profile is denied until the table is extended, so a future enum addition can
// never silently admit.
//
// Both inputs are DEPLOYMENT-level, never per-request: the tier comes from
// -runtime-tier and the profile from -workload-profile, each validated as a
// closed enum at startup. The matrix therefore cannot be steered by a request
// body; the lifecycle layer holds both as fixed fields and calls Decide with
// them, surfacing a rejection at the create path's admit stage BEFORE any host
// state exists.
//
// The package imports only internal/runtime (for RuntimeTier); it touches no
// state, no clock, no I/O, which is what makes the totality property test a pure
// function call over the whole input space.
package admission

import (
	"errors"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// WorkloadProfile is the deployment-DECLARED trust profile, set from
// -workload-profile exactly like the tier and NEVER per-request. The set is
// closed: a new profile adds a value here and a row to the matrix, or it is
// rejected by the fail-closed default.
type WorkloadProfile uint8

const (
	// ProfileTrustedOperator is a human operator or SOAR-driven workload — the
	// most trusted profile, admitted on the shared-kernel tiers.
	ProfileTrustedOperator WorkloadProfile = iota
	// ProfileInternalWorkforce is an internal automated workforce — admitted only
	// at gVisor or stronger, never on bare runc.
	ProfileInternalWorkforce
	// ProfileUntrusted is an untrusted or external workload — admitted only on a
	// microVM boundary, which is not in v1 GA, so it is rejected on every shipped
	// tier.
	ProfileUntrusted
)

// String renders the profile for the rejection text and audit record. An
// out-of-range value renders as "workload_profile_unknown" so a forgotten arm is
// visible rather than mislabelled.
func (p WorkloadProfile) String() string {
	switch p {
	case ProfileTrustedOperator:
		return "trusted_operator"
	case ProfileInternalWorkforce:
		return "internal_workforce"
	case ProfileUntrusted:
		return "untrusted"
	default:
		return "workload_profile_unknown"
	}
}

// RejectReason classifies a rejection so the typed error can tell a roadmap gap
// (microVM tier not yet shipped) apart from a policy violation (this profile may
// not run on this tier at all). The split matters operationally: the first is
// "wait for the microVM tier," the second is "your profile is too low for this
// tier."
type RejectReason uint8

const (
	// ReasonNone is the admitted case — no rejection.
	ReasonNone RejectReason = iota
	// ReasonPairingRejected means the profile may not run on this tier at all: the
	// pairing is a policy violation regardless of what is shipped (e.g. untrusted
	// on a shared-kernel tier).
	ReasonPairingRejected
	// ReasonMicroVMNotShipped means the pairing is conceptually valid but the
	// microVM tier (TierFirecracker) is not in v1 GA, so the create is refused as a
	// roadmap gap rather than a policy violation.
	ReasonMicroVMNotShipped
	// ReasonUnknownCell is the fail-closed default for an unknown profile or tier
	// enum value — denied until the matrix is extended.
	ReasonUnknownCell
)

// String renders the reason for the rejection text and audit record.
func (r RejectReason) String() string {
	switch r {
	case ReasonNone:
		return "admitted"
	case ReasonPairingRejected:
		return "profile may not run on this tier"
	case ReasonMicroVMNotShipped:
		return "microVM tier not in v1 GA"
	case ReasonUnknownCell:
		return "unknown profile or tier (fail-closed)"
	default:
		return "reject_reason_unknown"
	}
}

// Decision is the total result of Decide. Admitted is the single authority bit;
// Reason classifies the outcome (ReasonNone when Admitted is true).
type Decision struct {
	// Admitted is true only for the three v1-GA valid pairings.
	Admitted bool
	// Reason classifies a rejection, or is ReasonNone when Admitted is true.
	Reason RejectReason
}

// cell is one matrix entry. Encoding the table as data (rather than a switch
// chain) makes the totality and exactly-3-admit properties a direct count over a
// fixed structure, and a new pairing is a one-line table edit.
type cell struct {
	admitted bool
	reason   RejectReason
}

// numProfiles and numTiers bound the in-range grid. Decide treats any value at or
// beyond these as an unknown enum and rejects with ReasonUnknownCell.
const (
	numProfiles = 3
	numTiers    = 3
)

// matrix is the 3×3 admission table indexed by [profile][tier]. The three
// Admitted cells are the v1-GA valid pairings; the other six reject, split
// between pairing-rejected (the profile may not run on the tier at all) and
// microVM-not-shipped (the pairing is valid but TierFirecracker is not in v1 GA).
//
//	tier →            TierRunc                TierGvisor              TierFirecracker
//	profile ↓
//	TrustedOperator   ADMIT                   ADMIT                   microVM-not-shipped
//	InternalWorkforce pairing-rejected        ADMIT                   microVM-not-shipped
//	Untrusted         pairing-rejected        pairing-rejected        microVM-not-shipped
var matrix = [numProfiles][numTiers]cell{
	ProfileTrustedOperator: {
		runtime.TierRunc:        {admitted: true, reason: ReasonNone},
		runtime.TierGvisor:      {admitted: true, reason: ReasonNone},
		runtime.TierFirecracker: {admitted: false, reason: ReasonMicroVMNotShipped},
	},
	ProfileInternalWorkforce: {
		runtime.TierRunc:        {admitted: false, reason: ReasonPairingRejected},
		runtime.TierGvisor:      {admitted: true, reason: ReasonNone},
		runtime.TierFirecracker: {admitted: false, reason: ReasonMicroVMNotShipped},
	},
	ProfileUntrusted: {
		runtime.TierRunc:        {admitted: false, reason: ReasonPairingRejected},
		runtime.TierGvisor:      {admitted: false, reason: ReasonPairingRejected},
		runtime.TierFirecracker: {admitted: false, reason: ReasonMicroVMNotShipped},
	},
}

// Decide is the TOTAL admission function. Every (profile, tier) in the 3×3 grid
// maps to exactly one Decision; any profile or tier value outside the grid
// REJECTS with ReasonUnknownCell (fail-closed — a new tier or profile is denied
// until the matrix is extended). It is pure: no I/O, no clock, no host state, and
// it never panics for any uint8 input. The bounds check is explicit so an
// out-of-range enum indexes nothing — it returns the fail-closed cell directly.
func Decide(profile WorkloadProfile, tier runtime.RuntimeTier) Decision {
	if profile >= numProfiles || tier >= numTiers {
		return Decision{Admitted: false, Reason: ReasonUnknownCell}
	}
	c := matrix[profile][tier]
	return Decision{Admitted: c.admitted, Reason: c.reason}
}

// ErrAdmissionRejected is the hard typed error the lifecycle admit stage returns
// when Decide does not admit. The classifying RejectReason rides RejectedError,
// which wraps this sentinel so a caller can recover the reason for the
// audit/refusal text while still matching with errors.Is.
var ErrAdmissionRejected = errors.New("admission: profile and tier rejected")

// RejectedError wraps ErrAdmissionRejected with the classifying reason. The
// lifecycle returns this from the admit stage; errors.Is(err, ErrAdmissionRejected)
// holds, and a caller that needs the split inspects Reason directly.
type RejectedError struct {
	// Reason is the classification Decide produced for the refused pairing.
	Reason RejectReason
}

// Error renders the rejection with its reason for operator-facing text.
func (e RejectedError) Error() string {
	return fmt.Sprintf("admission: profile and tier rejected: %s", e.Reason)
}

// Unwrap exposes the sentinel so errors.Is(err, ErrAdmissionRejected) holds.
func (e RejectedError) Unwrap() error {
	return ErrAdmissionRejected
}
