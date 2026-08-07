// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Rotation fires at boot, before the audit writer opens anything (ADR-0009 /
// NFR-COMP-01). Boot is where it belongs because RotateSegment is
// read-then-truncate by path: an external process racing the live writer would
// destroy any envelope appended between the read and the truncate, after the
// action was already acked. Rotation of a live spine executes in-process.
//
// The hot file is empty after a rotation, so the ordinary resume path would
// read a legitimate genesis and re-anchor the chain — the rotation itself would
// manufacture the break the design forbids. The boot flow must resume from the
// sealed segment.

// hotSpine writes n records into a fresh hot file at dir and returns the path.
func hotSpine(t *testing.T, dir string, n int, at time.Time) string {
	t.Helper()
	path := filepath.Join(dir, "audit.ocsf.jsonl")
	fs, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	clk := state.NewFakeClock(at)
	tip, err := ocsf.ReadTip(path)
	if err != nil {
		t.Fatalf("ReadTip: %v", err)
	}
	sink := ocsf.ResumeChainSink(clk, fs, auditChainSource, tip)
	for i := 0; i < n; i++ {
		if err := sink.Emit(context.Background(), audit.Record{
			Action: audit.ActionRevokeOne, Channel: "operator", Key: "k",
		}); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

// TestBootRotationSealsAnOverdueSpine is the join at boot. A hot file whose
// first event predates the hot window must be sealed before the daemon appends
// to it — that is what bounds the file the boot verifier reads.
func TestBootRotationSealsAnOverdueSpine(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-100*24*time.Hour))
	cold := filepath.Join(dir, "cold")

	res, err := rotateAuditAtBoot(hot, cold, now)
	if err != nil {
		t.Fatalf("rotateAuditAtBoot: %v", err)
	}
	if !res.Rotated {
		t.Fatal("a 100-day-old spine was not sealed at boot; the hot file the boot " +
			"verifier reads stays unbounded")
	}

	remaining, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("the hot file still holds %d bytes after a boot rotation", len(remaining))
	}
	if _, err := ocsf.ReadChainFile(res.SegmentPath); err != nil {
		t.Errorf("the sealed segment does not read: %v", err)
	}
}

// TestBootRotationLeavesAFreshSpineAlone is the other arm. A daemon restarting
// inside the hot window must not seal — otherwise every restart produces a
// segment and the cold tier fills with fragments.
func TestBootRotationLeavesAFreshSpineAlone(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-24*time.Hour))
	cold := filepath.Join(dir, "cold")

	res, err := rotateAuditAtBoot(hot, cold, now)
	if err != nil {
		t.Fatalf("rotateAuditAtBoot: %v", err)
	}
	if res.Rotated {
		t.Error("a one-day-old spine was sealed at boot; every restart would produce " +
			"a segment and the cold tier would fill with fragments")
	}
	envs, err := ocsf.ReadChainFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	if len(envs) != 3 {
		t.Errorf("the hot file holds %d events, want the original 3", len(envs))
	}
}

// TestBootRotationDerivesTheWindowFromTheFirstEvent pins where sealedAt comes
// from. Nothing persists when the current segment began, and the alternatives
// are worse: mtime moves on every append, so an active spine would never be due
// and rotation would starve hardest on the busiest deployments.
//
// The first retained envelope's own event time is self-describing and needs no
// new state. This test proves the derivation is used by moving ONLY that time.
func TestBootRotationDerivesTheWindowFromTheFirstEvent(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	// Same event count, same everything, differing only in when the first event
	// was written. One is due, the other is not.
	fresh := t.TempDir()
	hotFresh := hotSpine(t, fresh, 3, now.Add(-10*24*time.Hour))
	overdue := t.TempDir()
	hotOverdue := hotSpine(t, overdue, 3, now.Add(-200*24*time.Hour))

	resFresh, err := rotateAuditAtBoot(hotFresh, filepath.Join(fresh, "cold"), now)
	if err != nil {
		t.Fatalf("fresh: %v", err)
	}
	resOverdue, err := rotateAuditAtBoot(hotOverdue, filepath.Join(overdue, "cold"), now)
	if err != nil {
		t.Fatalf("overdue: %v", err)
	}

	if resFresh.Rotated {
		t.Error("a 10-day-old spine was sealed; the window is not being read from the " +
			"first event")
	}
	if !resOverdue.Rotated {
		t.Error("a 200-day-old spine was not sealed; the window is not being read from " +
			"the first event")
	}
}

// TestBootRotationIsOffWithoutAColdDir keeps the feature opt-in. A deployment
// that names no cold tier has nowhere to put a segment, and sealing into a
// default path would scatter archived history somewhere the operator never
// chose.
func TestBootRotationIsOffWithoutAColdDir(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-100*24*time.Hour))

	res, err := rotateAuditAtBoot(hot, "", now)
	if err != nil {
		t.Fatalf("rotateAuditAtBoot with no cold dir: %v", err)
	}
	if res.Rotated {
		t.Error("rotation ran with no cold directory configured")
	}
	envs, err := ocsf.ReadChainFile(hot)
	if err != nil || len(envs) != 3 {
		t.Errorf("the hot file was disturbed: %d events, err=%v", len(envs), err)
	}
}

// TestBootRotationSkipsTheNonDurableOptOut matches the audit sink's own escape
// hatch. With -audit-sink=none there is no on-disk spine at all, so a rotation
// attempt would fail on a path that is not a file.
func TestBootRotationSkipsTheNonDurableOptOut(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, path := range []string{"none", "null", "NONE"} {
		t.Run(path, func(t *testing.T) {
			res, err := rotateAuditAtBoot(path, t.TempDir(), now)
			if err != nil {
				t.Errorf("rotateAuditAtBoot(%q) = %v, want a silent skip", path, err)
			}
			if res.Rotated {
				t.Errorf("rotation ran against the non-durable sink %q", path)
			}
		})
	}
}

// TestNonDurableSinkIsNeverTreatedAsAPath binds the sentinel skip to what only
// it does: no filesystem access at all for "none".
//
// The skip is otherwise invisible — firstEventTime returns a zero time for a
// path that does not exist, and the policy refuses a zero seal time, so the
// rotation is declined either way. Mutation testing showed deleting the guard
// changes no outcome. What it prevents is a sentinel being resolved as a
// relative path: a file literally named "none" in the working directory would
// otherwise be read, validated, and eventually sealed as if it were the spine.
func TestNonDurableSinkIsNeverTreatedAsAPath(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	// A real, overdue spine at a file literally named "none", and a working
	// directory that makes the sentinel resolve to it.
	planted := hotSpine(t, dir, 3, now.Add(-100*24*time.Hour))
	if err := os.Rename(planted, filepath.Join(dir, "none")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	res, err := rotateAuditAtBoot("none", filepath.Join(dir, "cold"), now)
	if err != nil {
		t.Fatalf("rotateAuditAtBoot(none): %v", err)
	}
	if res.Rotated {
		t.Fatal("the non-durable sentinel was resolved as a relative path and the file " +
			"named \"none\" was sealed as if it were the audit spine")
	}
	if _, err := os.Stat(filepath.Join(dir, "cold")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a cold directory was created for the non-durable sink")
	}
}

// TestBootRotationOnAnEmptySpineIsASilentSkip covers first boot. There is no
// file yet, or an empty one, and neither is an error — the daemon is starting
// for the first time.
func TestBootRotationOnAnEmptySpineIsASilentSkip(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	t.Run("absent", func(t *testing.T) {
		res, err := rotateAuditAtBoot(filepath.Join(dir, "nope.jsonl"),
			filepath.Join(dir, "cold"), now)
		if err != nil {
			t.Errorf("an absent spine = %v, want a silent skip", err)
		}
		if res.Rotated {
			t.Error("rotation reported success against an absent spine")
		}
	})

	t.Run("empty", func(t *testing.T) {
		empty := filepath.Join(dir, "empty.jsonl")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatalf("write empty: %v", err)
		}
		res, err := rotateAuditAtBoot(empty, filepath.Join(dir, "cold"), now)
		if err != nil {
			t.Errorf("an empty spine = %v, want a silent skip", err)
		}
		if res.Rotated {
			t.Error("rotation reported success against an empty spine")
		}
	})
}

// TestResumeAfterBootRotationContinuesTheSpine is the seam that makes boot
// rotation safe. After a rotation the hot file is EMPTY, so the ordinary resume
// path reads a legitimate genesis and the next event starts at sequence 1 with
// no prior link — the rotation would manufacture the chain break it exists to
// prevent, and both files would still validate on their own.
//
// The resumed sink must therefore carry the sealed segment's tail.
func TestResumeAfterBootRotationContinuesTheSpine(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-100*24*time.Hour))

	res, err := rotateAuditAtBoot(hot, filepath.Join(dir, "cold"), now)
	if err != nil || !res.Rotated {
		t.Fatalf("rotateAuditAtBoot: rotated=%v err=%v", res.Rotated, err)
	}

	tip, err := resumeTipAfterBootRotation(hot, res)
	if err != nil {
		t.Fatalf("resumeTipAfterBootRotation: %v", err)
	}

	sealedEnvs, err := ocsf.ReadChainFile(res.SegmentPath)
	if err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	tail := sealedEnvs[len(sealedEnvs)-1]
	if tip.Fresh {
		t.Fatal("the resume tip reports Fresh after a rotation; the next event would " +
			"start at sequence 1 and the spine would silently re-anchor")
	}
	if tip.LastSeq != tail.Sequence || tip.PriorTip != tail.Hash {
		t.Errorf("tip is seq=%d prior=%s, the sealed tail is seq=%d hash=%s",
			tip.LastSeq, tip.PriorTip, tail.Sequence, tail.Hash)
	}
}

// TestResumeWithoutARotationReadsTheHotFile is the unrotated path, kept as a
// separate arm so the seam cannot be satisfied by always reading the segment —
// there is no segment on an ordinary boot.
func TestResumeWithoutARotationReadsTheHotFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-24*time.Hour))

	res, err := rotateAuditAtBoot(hot, filepath.Join(dir, "cold"), now)
	if err != nil {
		t.Fatalf("rotateAuditAtBoot: %v", err)
	}
	if res.Rotated {
		t.Fatal("a fresh spine rotated; this test needs the unrotated path")
	}

	tip, err := resumeTipAfterBootRotation(hot, res)
	if err != nil {
		t.Fatalf("resumeTipAfterBootRotation: %v", err)
	}
	envs, err := ocsf.ReadChainFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	last := envs[len(envs)-1]
	if tip.LastSeq != last.Sequence || tip.PriorTip != last.Hash {
		t.Errorf("tip is seq=%d, the hot tail is seq=%d", tip.LastSeq, last.Sequence)
	}
}

// TestAuditColdDirFlagIsAccepted binds the operator-facing surface. The
// rotation code is unreachable without a flag that names the cold tier, and a
// feature nothing can turn on is not shipped.
func TestAuditColdDirFlagIsAccepted(t *testing.T) {
	cfg, _, err := parse([]string{
		"-audit-sink", filepath.Join(t.TempDir(), "audit.jsonl"),
		"-audit-cold-dir", "/var/lib/ocu/audit-cold",
	})
	if err != nil {
		t.Fatalf("parse with -audit-cold-dir: %v", err)
	}
	if cfg.auditColdDir != "/var/lib/ocu/audit-cold" {
		t.Errorf("auditColdDir = %q, want the configured path", cfg.auditColdDir)
	}
}

// TestAuditColdDirDefaultsToOff keeps rotation opt-in. An unset flag must leave
// the field empty, which is what rotateAuditAtBoot reads as "do nothing" — a
// default path would scatter archived history somewhere the operator never
// chose.
func TestAuditColdDirDefaultsToOff(t *testing.T) {
	cfg, _, err := parse([]string{
		"-audit-sink", filepath.Join(t.TempDir(), "audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.auditColdDir != "" {
		t.Errorf("auditColdDir defaults to %q; rotation would run unasked", cfg.auditColdDir)
	}
}

// TestResumedSinkContinuesAcrossABootRotation drives the REAL boot pieces in
// order — rotate, open the writer, build the resumed sink — and emits through
// it. This is the wiring test: the helpers can each be right while run() feeds
// them in the wrong order or not at all.
//
// The whole spine (sealed segment + hot file) must validate as ONE chain
// afterwards. That is the property the seam exists for, and it is exactly what
// each half validating alone cannot show.
func TestResumedSinkContinuesAcrossABootRotation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-100*24*time.Hour))
	cold := filepath.Join(dir, "cold")

	// The boot sequence, as run() performs it.
	rotated, err := rotateAuditAtBoot(hot, cold, now)
	if err != nil || !rotated.Rotated {
		t.Fatalf("rotate: rotated=%v err=%v", rotated.Rotated, err)
	}
	writer, err := buildAuditWriter(hot)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	sink, err := buildResumedChainSink(context.Background(), state.NewFakeClock(now), writer, hot, rotated)
	if err != nil {
		t.Fatalf("buildResumedChainSink: %v", err)
	}
	if err := sink.Emit(context.Background(), audit.Record{
		Action: audit.ActionRevokeOne, Channel: "operator", Key: "k",
	}); err != nil {
		t.Fatalf("emit after rotation: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	sealedEnvs, err := ocsf.ReadChainFile(rotated.SegmentPath)
	if err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	hotEnvs, err := ocsf.ReadChainFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	if len(hotEnvs) != 1 {
		t.Fatalf("the hot file holds %d events after one emit, want 1", len(hotEnvs))
	}

	whole := append(append([]ocsf.ChainEnvelope{}, sealedEnvs...), hotEnvs...)
	if err := ocsf.ValidateChain(whole); err != nil {
		t.Fatalf("the sealed segment and the post-boot hot file do not form one "+
			"spine: %v — the resumed sink re-anchored and the rotation manufactured "+
			"the exact chain break it exists to prevent", err)
	}
}

// TestBootRotationRefusesATamperedSpine keeps the fail-closed posture. The
// daemon already aborts at boot on an invalid chain; rotation must not be the
// step that launders one into the archive first.
func TestBootRotationRefusesATamperedSpine(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	hot := hotSpine(t, dir, 3, now.Add(-100*24*time.Hour))

	raw, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	mutated := strings.Replace(string(raw), `"reason":""`, `"reason":"x"`, 1)
	if mutated == string(raw) {
		t.Fatal("the mutation did not apply; this test would pass vacuously")
	}
	if err := os.WriteFile(hot, []byte(mutated), 0o600); err != nil {
		t.Fatalf("write mutated: %v", err)
	}

	if _, err := rotateAuditAtBoot(hot, filepath.Join(dir, "cold"), now); !errors.Is(err, ocsf.ErrChainInvalid) {
		t.Errorf("a tampered spine at boot = %v, want ErrChainInvalid", err)
	}
}
