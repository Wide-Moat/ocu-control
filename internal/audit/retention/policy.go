// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package retention decides what may be removed from the audit trail and when
// (NFR-COMP-01).
//
// ADR-0009 puts retention-policy enforcement on OCU's build side and leaves the
// WORM store to the customer. This package is the enforcement half: it removes
// nothing, reads nothing, and knows nothing about a substrate. Callers that do
// remove things route through it.
//
// The floor is a MINIMUM. Every regulation behind NFR-COMP-01 fixes how long
// records must be kept, never when they must be destroyed, so the load-bearing
// property here is the refusal of a premature deletion rather than the
// performance of a timely one. Post-floor disposal is the deployment's
// lifecycle policy.
//
// On the minimal shelf this is enforcement at the only point OCU owns: OCU's own
// delete paths. NFR-COMP-01 says so directly — the minimal shelf is
// tamper-EVIDENT via the hash chain and the signed Merkle head, not
// WORM-immutable, and a threat model needing immutability against a privileged
// actor wires the WORM seam.
package retention

import (
	"errors"
	"fmt"
	"time"
)

const (
	// year is the retention year NFR-COMP-01's floor is counted in. Leap days
	// make a "year" ambiguous; 365 days is the conservative reading, because a
	// shorter year would retire records marginally early.
	year = 365 * 24 * time.Hour

	// DefaultFloor is the 7-year floor a deployment gets when it configures
	// nothing — the case most likely to be audited against the regulation.
	DefaultFloor = 7 * year

	// TenYearFloor is the configurable ceiling NFR-COMP-01 names. It is not a
	// maximum: a deployment may set anything at or above DefaultFloor, and this
	// constant exists so the common case reads by name.
	TenYearFloor = 10 * year

	// DefaultHotWindow is the <=90d hot tier. A segment older than this is due
	// for rotation to the cold tier — which is not a deletion (see MayDelete).
	DefaultHotWindow = 90 * 24 * time.Hour
)

var (
	// ErrBelowFloor refuses a configured floor under the regulatory minimum.
	// "7 y default / 10 y configurable" means configurable UPWARD.
	ErrBelowFloor = errors.New("retention: floor is below the regulatory minimum")

	// ErrHotWindowTooLong refuses a hot tier that outlives the floor, which
	// would make a segment deletable before it was ever rotated.
	ErrHotWindowTooLong = errors.New("retention: hot window outlives the retention floor")

	// ErrHotWindowInvalid refuses a non-positive hot window.
	ErrHotWindowInvalid = errors.New("retention: hot window must be positive")

	// ErrWithinFloor is the premature-deletion refusal — the property a
	// regulated-enterprise reviewer tests by attempting an early removal.
	ErrWithinFloor = errors.New("retention: record is still within the retention floor")

	// ErrUnknownWriteTime refuses a record whose write time is missing. A zero
	// time arithmetically reads as arbitrarily old, so admitting it would exempt
	// exactly the records whose metadata failed to load.
	ErrUnknownWriteTime = errors.New("retention: record has no write time")

	// ErrWriteTimeInFuture refuses a record stamped ahead of now. Its age would
	// be negative, and treating that as old enough would let a clock setback
	// authorise deleting everything.
	ErrWriteTimeInFuture = errors.New("retention: record write time is in the future")
)

// Config is the deployment's retention configuration. The zero value is valid
// and yields the NFR-COMP-01 defaults.
type Config struct {
	// Floor is the minimum retention period. Zero means DefaultFloor. A value
	// below DefaultFloor is refused rather than clamped: silently raising an
	// operator's number would leave them believing a shorter period is in force.
	Floor time.Duration

	// HotWindow is how long a segment stays in the hot tier. Zero means
	// DefaultHotWindow.
	HotWindow time.Duration
}

// Policy answers two questions and performs no action: whether a segment is due
// to rotate, and whether a record may be deleted.
type Policy struct {
	floor     time.Duration
	hotWindow time.Duration
}

// NewPolicy validates a configuration and returns the policy it describes.
func NewPolicy(cfg Config) (*Policy, error) {
	floor := cfg.Floor
	if floor == 0 {
		floor = DefaultFloor
	}
	if floor < DefaultFloor {
		return nil, fmt.Errorf("%w: %v is under the %v minimum", ErrBelowFloor, floor, DefaultFloor)
	}

	hot := cfg.HotWindow
	if hot == 0 {
		hot = DefaultHotWindow
	}
	if hot <= 0 {
		return nil, fmt.Errorf("%w: %v", ErrHotWindowInvalid, hot)
	}
	if hot >= floor {
		return nil, fmt.Errorf("%w: hot window %v, floor %v", ErrHotWindowTooLong, hot, floor)
	}

	return &Policy{floor: floor, hotWindow: hot}, nil
}

// Floor is the configured minimum retention period.
func (p *Policy) Floor() time.Duration { return p.floor }

// HotWindow is how long a segment stays in the hot tier before rotating.
func (p *Policy) HotWindow() time.Duration { return p.hotWindow }

// ShouldRotate reports whether a segment sealed at sealedAt is due to move to
// the cold tier.
//
// Rotation is not deletion. A segment rotates while it is still deep inside the
// retention floor — that is what a hot tier is for — so a caller must not read
// a true here as permission to remove anything. MayDelete answers that.
func (p *Policy) ShouldRotate(sealedAt, now time.Time) bool {
	if sealedAt.IsZero() || sealedAt.After(now) {
		return false
	}
	return now.Sub(sealedAt) >= p.hotWindow
}

// MayDelete reports whether a record written at writtenAt may be removed, and
// refuses with a named reason otherwise.
//
// The boundary is inclusive: a record retained for exactly the floor has served
// the full period.
func (p *Policy) MayDelete(writtenAt, now time.Time) error {
	if writtenAt.IsZero() {
		return ErrUnknownWriteTime
	}
	if writtenAt.After(now) {
		return fmt.Errorf("%w: written %v, now %v", ErrWriteTimeInFuture, writtenAt, now)
	}

	age := now.Sub(writtenAt)
	if age < p.floor {
		return fmt.Errorf("%w: age %v, floor %v", ErrWithinFloor, age, p.floor)
	}
	return nil
}
