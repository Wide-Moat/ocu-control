// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention_test

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
	"github.com/Wide-Moat/ocu-control/internal/audit/retention"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// The driver joins the two halves already built: the policy says WHETHER a
// segment is due (ShouldRotate), and ocsf.RotateSegment does the sealing. It
// holds neither policy nor mechanism — it decides when to call, and reports
// what happened.
//
// This package is _test so the driver is exercised through its exported
// surface, the same way the daemon will use it.
//
// The properties worth pinning are about repeated calls and about what the
// caller learns, because the driver runs on a timer nobody watches.

// spineAt writes n records into a fresh hot file and returns its path.
func spineAt(t *testing.T, dir string, n int) string {
	t.Helper()
	path := filepath.Join(dir, "audit.ocsf.jsonl")
	fs, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	tip, err := ocsf.ReadTip(path)
	if err != nil {
		t.Fatalf("ReadTip: %v", err)
	}
	sink := ocsf.ResumeChainSink(state.SystemClock(), fs, "control", tip)
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

func testPolicy(t *testing.T) *retention.Policy {
	t.Helper()
	p, err := retention.NewPolicy(retention.Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

// TestDriverRotatesOnlyWhenTheHotTierIsDue is the join. A segment younger than
// the hot window must be left alone; one older must be sealed. Both arms are
// required — a driver that always rotates and one that never does each satisfy
// half of this.
func TestDriverRotatesOnlyWhenTheHotTierIsDue(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	p := testPolicy(t)

	t.Run("inside the hot window", func(t *testing.T) {
		dir := t.TempDir()
		hot := spineAt(t, dir, 3)
		cold := filepath.Join(dir, "cold")

		res, err := retention.RotateIfDue(p, hot, cold, now.Add(-24*time.Hour), now)
		if err != nil {
			t.Fatalf("RotateIfDue: %v", err)
		}
		if res.Rotated {
			t.Error("a one-day-old segment was rotated; the hot tier would be empty")
		}
		if _, err := os.Stat(cold); !errors.Is(err, os.ErrNotExist) {
			t.Error("a skipped rotation created the cold directory")
		}
	})

	t.Run("past the hot window", func(t *testing.T) {
		dir := t.TempDir()
		hot := spineAt(t, dir, 3)
		cold := filepath.Join(dir, "cold")

		res, err := retention.RotateIfDue(p, hot, cold, now.Add(-100*24*time.Hour), now)
		if err != nil {
			t.Fatalf("RotateIfDue: %v", err)
		}
		if !res.Rotated {
			t.Fatal("a 100-day-old segment was not rotated; the hot window is 90 days")
		}
		if res.SegmentPath == "" {
			t.Error("a rotation reported no segment path; the caller cannot find what " +
				"it must hand to the cold tier")
		}
		if res.Events != 3 {
			t.Errorf("rotation reported %d events, the hot file held 3", res.Events)
		}
	})
}

// TestSecondCallDoesNotRotateAgain is the idempotence property. The driver runs
// on a timer; a second firing before any new events must be a no-op rather than
// an error or an empty segment.
func TestSecondCallDoesNotRotateAgain(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	p := testPolicy(t)
	dir := t.TempDir()
	hot := spineAt(t, dir, 3)
	cold := filepath.Join(dir, "cold")
	sealedAt := now.Add(-100 * 24 * time.Hour)

	first, err := retention.RotateIfDue(p, hot, cold, sealedAt, now)
	if err != nil || !first.Rotated {
		t.Fatalf("first call: rotated=%v err=%v", first.Rotated, err)
	}

	second, err := retention.RotateIfDue(p, hot, cold, sealedAt, now)
	if err != nil {
		t.Fatalf("the second call errored instead of reporting nothing to do: %v", err)
	}
	if second.Rotated {
		t.Error("the second call rotated again; the hot file was empty, so the cold " +
			"tier would gain a segment witnessing no events")
	}

	ents, err := os.ReadDir(cold)
	if err != nil {
		t.Fatalf("read cold: %v", err)
	}
	if len(ents) != 1 {
		t.Errorf("the cold tier holds %d segments after two calls, want 1", len(ents))
	}
}

// TestDriverReportsTheSealedRangeSoAHeadCanBeTaken carries the caller's next
// step. NFR-SEC-03 witnesses the sealed segment with a Merkle head, so a
// rotation that did not say WHICH range it sealed leaves the caller unable to
// take one without re-reading the directory and guessing.
func TestDriverReportsTheSealedRangeSoAHeadCanBeTaken(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	p := testPolicy(t)
	dir := t.TempDir()
	hot := spineAt(t, dir, 4)

	res, err := retention.RotateIfDue(p, hot, filepath.Join(dir, "cold"),
		now.Add(-100*24*time.Hour), now)
	if err != nil || !res.Rotated {
		t.Fatalf("RotateIfDue: rotated=%v err=%v", res.Rotated, err)
	}

	envs, err := ocsf.ReadChainFile(res.SegmentPath)
	if err != nil {
		t.Fatalf("the reported segment path does not read: %v", err)
	}
	head, err := ocsf.HeadOverSpine(envs)
	if err != nil {
		t.Fatalf("no head can be taken over the reported segment: %v", err)
	}
	if head.Count != res.Events {
		t.Errorf("the head covers %d events, the driver reported %d", head.Count, res.Events)
	}
	if res.FirstSequence != head.FirstSequence || res.LastSequence != head.LastSequence {
		t.Errorf("the driver reported range %d-%d, the head covers %d-%d",
			res.FirstSequence, res.LastSequence, head.FirstSequence, head.LastSequence)
	}
}

// TestDriverDoesNotRotateAnEmptyHotFile keeps a due-but-empty window from
// producing a segment. It is distinct from the second-call case: there the file
// was emptied by a rotation, here it was never written to.
func TestDriverDoesNotRotateAnEmptyHotFile(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	p := testPolicy(t)
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	if err := os.WriteFile(hot, nil, 0o600); err != nil {
		t.Fatalf("write empty hot: %v", err)
	}

	res, err := retention.RotateIfDue(p, hot, filepath.Join(dir, "cold"),
		now.Add(-100*24*time.Hour), now)
	if err != nil {
		t.Fatalf("an empty due window errored: %v", err)
	}
	if res.Rotated {
		t.Error("an empty hot file was rotated into a segment")
	}
}

// TestDriverSurfacesARotationFailure keeps a broken rotation loud. The driver
// runs unattended, so swallowing the error would leave the hot file growing
// without bound and nothing reporting why.
func TestDriverSurfacesARotationFailure(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	p := testPolicy(t)
	dir := t.TempDir()
	hot := spineAt(t, dir, 3)

	// A cold "directory" that is a file: sealing into it cannot succeed.
	blocked := filepath.Join(dir, "cold-is-a-file")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	res, err := retention.RotateIfDue(p, hot, blocked, now.Add(-100*24*time.Hour), now)
	if err == nil {
		t.Fatal("a failed rotation reported success; the hot file would grow unbounded " +
			"with nothing saying why")
	}
	if res.Rotated {
		t.Error("a failed rotation reported Rotated=true")
	}

	// The error must name the rotation, not a later step. Swallowing
	// RotateSegment's error still fails this call — the empty segment path makes
	// the describe step error instead — so the non-nil check above does not bind
	// the propagation. Mutation testing surfaced that.
	//
	// The difference is what an operator reads at 3am: "rotate <hot>: ..." points
	// at the cold destination, while a describe-step failure points at a segment
	// that was never created and sends them looking for a missing file.
	if !strings.Contains(err.Error(), "rotate") {
		t.Errorf("the failure is reported as %q, which does not name the rotation; "+
			"the real cause was replaced by whatever failed next", err)
	}
	if strings.Contains(err.Error(), "describe sealed segment") {
		t.Errorf("the failure surfaced from the describe step (%q); RotateSegment's "+
			"error was discarded and the operator is pointed at a file that was "+
			"never created", err)
	}
}

// TestDriverRefusesAFutureSealTime fails closed on a clock anomaly, matching
// MayDelete. A seal time ahead of now makes the window negative, and treating
// that as "not due" would silently stop rotating.
func TestDriverRefusesAFutureSealTime(t *testing.T) {
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	p := testPolicy(t)
	dir := t.TempDir()
	hot := spineAt(t, dir, 3)

	_, err := retention.RotateIfDue(p, hot, filepath.Join(dir, "cold"),
		now.Add(time.Hour), now)
	if !errors.Is(err, retention.ErrSealTimeInFuture) {
		t.Errorf("a future seal time = %v, want ErrSealTimeInFuture; a wrong clock "+
			"would otherwise read as 'not due yet' and rotation would stop silently", err)
	}
}
