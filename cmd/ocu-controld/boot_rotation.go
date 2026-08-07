// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/audit/retention"
)

// Boot-time hot-to-cold rotation (NFR-COMP-01).
//
// It runs at the TOP of the audit setup, before the writer opens anything, and
// it runs in-process rather than from a timer or an external command. That is
// not a convenience: RotateSegment is read-then-truncate by path, so a separate
// process racing the live writer would destroy any envelope appended between
// the read and the truncate — after the action was already acknowledged.
//
// Rotation also bounds the file the boot verifier reads end to end, which is
// the cost note verifyAuditChainFile carries.

// rotateAuditAtBoot seals the hot spine when its oldest retained event has
// outlived the hot window. It reports what happened so the caller can resume the
// chain from the sealed segment: after a rotation the hot file is empty, and the
// ordinary resume path would read that as a legitimate genesis and re-anchor —
// the rotation would manufacture the chain break it exists to avoid.
//
// coldDir empty turns rotation off. A deployment that names no cold tier has
// nowhere to put a segment, and sealing into a default path would scatter
// archived history somewhere the operator never chose.
func rotateAuditAtBoot(auditPath, coldDir string, now time.Time) (retention.Result, error) {
	if coldDir == "" {
		return retention.Result{}, nil
	}
	// The non-durable opt-out names no file, so there is no spine to rotate.
	// Skipping it explicitly rather than relying on the read below to come back
	// empty: "none" is a sentinel, not a path, and a later change that made
	// firstEventTime resolve unknown paths differently would otherwise start
	// treating it as one.
	if auditSinkNone[strings.ToLower(auditPath)] {
		return retention.Result{}, nil
	}

	sealedAt, err := firstEventTime(auditPath)
	if err != nil {
		return retention.Result{}, err
	}

	policy, err := retention.NewPolicy(retention.Config{})
	if err != nil {
		return retention.Result{}, fmt.Errorf("retention policy: %w", err)
	}
	return retention.RotateIfDue(policy, auditPath, coldDir, sealedAt, now)
}

// firstEventTime reads when the oldest retained event was written, which is when
// the current hot segment began.
//
// Nothing persists that separately, and it needs nothing: the first envelope
// carries its own OCSF event time. The alternatives are worse — mtime moves on
// every append, so an active spine would never be due and rotation would starve
// hardest on the busiest deployments; a sidecar marker adds a second file whose
// crash-consistency relative to the spine then has to be reasoned about.
//
// A zero time means there is no first envelope, which the caller reads as
// nothing to rotate. That gap is exactly coextensive with having no events, so
// there is no question for the policy to answer.
func firstEventTime(path string) (time.Time, error) {
	envs, err := ocsf.ReadChainFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read audit spine %q: %w", path, err)
	}
	if len(envs) == 0 {
		return time.Time{}, nil
	}

	var ev struct {
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(envs[0].Event, &ev); err != nil {
		return time.Time{}, fmt.Errorf("read first event time from %q: %w", path, err)
	}
	if ev.Time == 0 {
		return time.Time{}, fmt.Errorf("first event in %q carries no time", path)
	}
	return time.UnixMilli(ev.Time).UTC(), nil
}

// resumeTipAfterBootRotation returns the tip a chain sink must resume from,
// given what rotation did this boot.
//
// After a rotation the hot file is empty and its own tip reports a legitimate
// genesis, so resuming from it would start the next event at sequence 1 with no
// prior link — the rotation would manufacture the chain break it exists to
// prevent, and both files would still validate on their own. The tip comes from
// the sealed segment instead.
//
// Without a rotation this is the ordinary read, so an unrotated boot behaves
// exactly as it did before rotation existed.
func resumeTipAfterBootRotation(auditPath string, res retention.Result) (ocsf.Tip, error) {
	if !res.Rotated {
		return ocsf.ReadTip(auditPath)
	}
	return ocsf.ResumeTipAfterRotation(auditPath, res.SegmentPath)
}
