// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"errors"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// The rotation driver joins the two halves: the policy says whether a segment is
// due, ocsf.RotateSegment does the sealing. It holds neither, and it schedules
// nothing — the caller decides when to ask.
//
// It runs unattended, so what it REPORTS is as load-bearing as what it does. A
// rotation that succeeded silently leaves the caller unable to take the Merkle
// head NFR-SEC-03 requires over the sealed range; a failure swallowed leaves the
// hot file growing without bound and nothing saying why.

// ErrSealTimeInFuture refuses a seal time ahead of now. The window would be
// negative, and reading that as "not due yet" would stop rotation silently —
// the same clock-anomaly failure MayDelete guards against, in the other verb.
var ErrSealTimeInFuture = errors.New("retention: segment seal time is in the future")

// Result is what one rotation attempt did. When Rotated is false the remaining
// fields are zero: there was nothing to seal.
type Result struct {
	// Rotated is true only when a segment was sealed on this call.
	Rotated bool
	// SegmentPath is the sealed segment, so the caller can take a head over it
	// without re-reading the cold directory and guessing which file is new.
	SegmentPath string
	// Events is how many envelopes the segment covers.
	Events uint64
	// FirstSequence and LastSequence bound the sealed range.
	FirstSequence uint64
	LastSequence  uint64
}

// RotateIfDue seals the hot file into coldDir when the policy says the current
// segment has outlived the hot tier.
//
// sealedAt is when the current hot segment began — the previous rotation, or
// the daemon's first write. A call before the window elapses is a no-op, and so
// is a call on an empty hot file: sealing nothing produces a segment that
// witnesses nothing, which a scheduler firing twice would otherwise file.
func RotateIfDue(p *Policy, hotPath, coldDir string, sealedAt, now time.Time) (Result, error) {
	if p == nil {
		return Result{}, errors.New("retention: nil policy")
	}
	if sealedAt.After(now) {
		return Result{}, fmt.Errorf("%w: sealed %v, now %v", ErrSealTimeInFuture, sealedAt, now)
	}
	if !p.ShouldRotate(sealedAt, now) {
		return Result{}, nil
	}

	segment, err := ocsf.RotateSegment(hotPath, coldDir)
	if errors.Is(err, ocsf.ErrNothingToRotate) {
		// Due, but there is nothing in the window. Not an error: a quiet period
		// is a legitimate state, and reporting it as one would make every idle
		// deployment noisy.
		return Result{}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("rotate %q: %w", hotPath, err)
	}

	// Read the sealed range back rather than tracking it through RotateSegment.
	// The segment is the artifact the caller acts on, so its own contents are
	// what the report must describe.
	envs, err := ocsf.ReadChainFile(segment)
	if err != nil {
		return Result{}, fmt.Errorf("describe sealed segment %q: %w", segment, err)
	}
	if len(envs) == 0 {
		return Result{}, fmt.Errorf("sealed segment %q holds no events", segment)
	}

	return Result{
		Rotated:       true,
		SegmentPath:   segment,
		Events:        uint64(len(envs)),
		FirstSequence: envs[0].Sequence,
		LastSequence:  envs[len(envs)-1].Sequence,
	}, nil
}
