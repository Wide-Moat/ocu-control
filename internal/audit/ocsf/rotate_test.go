// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// NFR-COMP-01's two-tier split needs the hot file to be sealed into a segment
// and handed to the cold tier. Component-07 owns the tier boundary; where a
// segment lands is a customer seam (ADR-0009), so rotation stops at producing
// a sealed segment and never knows what a WORM store is.
//
// Rotation is also load-bearing for the daemon itself: boot-time validation
// reads the whole hot file, which cmd/ocu-controld notes is acceptable only
// because rotation will bound it.
//
// The properties below are ordering properties. A rotation that loses events,
// or that breaks the chain across the seam, destroys the tamper-evidence the
// whole audit tract exists for — and does so silently, because each half still
// validates on its own.

// writeSpine emits n records through a real sink at path.
func writeSpine(t *testing.T, path string, n int) {
	t.Helper()
	fs, err := OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	tip, err := ReadTip(path)
	if err != nil {
		t.Fatalf("ReadTip: %v", err)
	}
	sink := ResumeChainSink(state.SystemClock(), fs, "control", tip)
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
}

// continueSpine emits n records into the post-rotation hot file, resuming from
// the sealed segment's tip the way a daemon must.
func continueSpine(t *testing.T, hotPath, sealedPath string, n int) {
	t.Helper()
	tip, err := ResumeTipAfterRotation(hotPath, sealedPath)
	if err != nil {
		t.Fatalf("ResumeTipAfterRotation: %v", err)
	}
	fs, err := OpenFileSink(hotPath)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	sink := ResumeChainSink(state.SystemClock(), fs, "control", tip)
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
}

// TestRotateKeepsTheChainUnbrokenAcrossTheSeam is the keystone. After rotation
// the sealed segment and the new hot file are two files, but they are ONE spine:
// concatenating them must validate, and the first event of the new file must
// link to the last event of the sealed one.
//
// A rotation that restarts the chain leaves both halves individually valid, so
// nothing short of this concatenation notices.
func TestRotateKeepsTheChainUnbrokenAcrossTheSeam(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 3)

	sealed, err := RotateSegment(hot, filepath.Join(dir, "cold"))
	if err != nil {
		t.Fatalf("RotateSegment: %v", err)
	}

	// Continue the spine in the new hot file, exactly as the daemon would: the
	// hot file is empty after rotation, so its own tip reports a legitimate
	// genesis. Resuming from THAT is what restarts the chain, which is the whole
	// reason ResumeTipAfterRotation exists.
	continueSpine(t, hot, sealed, 2)

	before, err := ReadChainFile(sealed)
	if err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	after, err := ReadChainFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	if len(before) != 3 || len(after) != 2 {
		t.Fatalf("segment holds %d and hot holds %d, want 3 and 2", len(before), len(after))
	}

	whole := append(append([]ChainEnvelope{}, before...), after...)
	if err := ValidateChain(whole); err != nil {
		t.Fatalf("the two halves do not form one spine: %v — rotation restarted the "+
			"chain, and each half validating alone hides it", err)
	}

	// Stated directly as well, so a ValidateChain that grew lax cannot mask it.
	if after[0].PriorHash != before[len(before)-1].Hash {
		t.Errorf("the first post-rotation event links to %q, the sealed tail is %q",
			after[0].PriorHash, before[len(before)-1].Hash)
	}
	if after[0].Sequence != before[len(before)-1].Sequence+1 {
		t.Errorf("sequence jumped from %d to %d across the seam",
			before[len(before)-1].Sequence, after[0].Sequence)
	}
}

// TestRotateLosesNoEvents is the count property, separate from the link
// property: a rotation could link correctly and still drop the tail it sealed.
func TestRotateLosesNoEvents(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 5)

	sealed, err := RotateSegment(hot, filepath.Join(dir, "cold"))
	if err != nil {
		t.Fatalf("RotateSegment: %v", err)
	}

	got, err := ReadChainFile(sealed)
	if err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if len(got) != 5 {
		t.Errorf("the sealed segment holds %d events, the hot file held 5", len(got))
	}
	for i, env := range got {
		if env.Sequence != uint64(i+1) {
			t.Errorf("sealed event %d carries sequence %d", i, env.Sequence)
		}
	}
}

// TestRotateCommitsColdBeforeTruncatingHot is the crash-safety ordering. If the
// hot file were truncated first, a crash between the two steps would lose every
// event in the window — permanently, and with both surviving files still
// validating.
//
// The check is direct: with the cold destination unwritable, rotation must fail
// AND leave the hot file whole.
func TestRotateCommitsColdBeforeTruncatingHot(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 4)

	before, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}

	// A cold "directory" that is actually a file: creating the segment inside it
	// cannot succeed.
	blocked := filepath.Join(dir, "cold-is-a-file")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	if _, err := RotateSegment(hot, blocked); err == nil {
		t.Fatal("rotation reported success with an unwritable cold destination")
	}

	after, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot after failed rotation: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("a FAILED rotation modified the hot file (%d bytes -> %d); the events "+
			"in the window are gone and nothing reports them missing",
			len(before), len(after))
	}
}

// TestRotateRefusesAnEmptyHotFile fails closed. Sealing nothing produces an
// empty segment that validates trivially and a head over no events, so a
// scheduler that ran twice would file a witness of nothing.
func TestRotateRefusesAnEmptyHotFile(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	if err := os.WriteFile(hot, nil, 0o600); err != nil {
		t.Fatalf("write empty hot: %v", err)
	}

	if _, err := RotateSegment(hot, filepath.Join(dir, "cold")); !errors.Is(err, ErrNothingToRotate) {
		t.Errorf("rotating an empty hot file = %v, want ErrNothingToRotate", err)
	}
}

// TestRotateRefusesATamperedHotFile keeps rotation from laundering a broken
// chain into the cold tier, where it becomes the archived record. A tampered
// spine must be caught at the boundary, not sealed and shipped.
func TestRotateRefusesATamperedHotFile(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 3)

	raw, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	mutated := strings.Replace(string(raw), `"reason":""`, `"reason":"x"`, 1)
	if mutated == string(raw) {
		t.Fatal("the mutation did not apply; this test would pass vacuously")
	}
	if err := os.WriteFile(hot, []byte(mutated), 0o600); err != nil {
		t.Fatalf("write mutated hot: %v", err)
	}

	cold := filepath.Join(dir, "cold")
	_, err = RotateSegment(hot, cold)
	if !errors.Is(err, ErrChainInvalid) {
		t.Errorf("rotating a TAMPERED hot file = %v, want ErrChainInvalid; a broken "+
			"chain would otherwise be sealed into the archive as the record of truth", err)
	}

	// No residue: whatever refused the rotation, the archive must be untouched.
	// A partial or unverified file there is named for a legitimate sequence
	// range, so an operator inventorying the cold tier reads it as retained
	// history and the next rotation of that range collides with it.
	ents, err := os.ReadDir(cold)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read cold dir: %v", err)
	}
	if len(ents) != 0 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("a refused rotation left %d file(s) in the cold tier (%v); the archive "+
			"now holds a segment that was never sealed", len(ents), names)
	}
}

// TestTamperedHotFileNeverReachesTheColdFilesystem binds the PRE-SEAL check
// specifically. The read-back verification catches the same tamper on the
// byte-identical copy, so the refusal above holds either way — mutation testing
// showed that deleting the earlier check changes no verdict.
//
// What it does change is whether a known-bad file is written at all. With the
// pre-seal check, a tampered hot file never touches the cold filesystem; without
// it, the file is created, fsynced, read back, rejected and removed. On a WORM
// substrate that sequence is not merely wasteful — a create may be the one
// operation the store will not let us undo.
//
// The cold directory standing in here is read-only, so any attempt to create a
// file in it fails. A build that seals first cannot get past that; a build that
// validates first never tries.
func TestTamperedHotFileNeverReachesTheColdFilesystem(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 3)

	raw, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot: %v", err)
	}
	mutated := strings.Replace(string(raw), `"reason":""`, `"reason":"x"`, 1)
	if mutated == string(raw) {
		t.Fatal("the mutation did not apply; this test would pass vacuously")
	}
	if err := os.WriteFile(hot, []byte(mutated), 0o600); err != nil {
		t.Fatalf("write mutated hot: %v", err)
	}

	cold := filepath.Join(dir, "cold-readonly")
	if err := os.Mkdir(cold, 0o500); err != nil {
		t.Fatalf("mkdir read-only cold: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cold, 0o700) })

	_, err = RotateSegment(hot, cold)
	if err == nil {
		t.Fatal("rotation succeeded against a read-only cold directory")
	}
	if !errors.Is(err, ErrChainInvalid) {
		t.Errorf("the refusal is %v, not a chain-validity verdict; the tamper was not "+
			"caught before the cold write was attempted, so a known-bad segment reached "+
			"the substrate", err)
	}
}

// TestPostWriteFailureLeavesNoResidue binds the cleanup path. The pre-seal
// validation means a tampered spine never creates a file, so that case cannot
// exercise cleanup — this one fails AFTER the cold copy exists.
//
// A colliding filename is the realistic trigger: a previous rotation of the same
// sequence range, an interrupted run, or a scheduler firing twice. The failure
// must leave the archive exactly as it found it, or a retry sees a directory
// littered with partial segments named for legitimate ranges.
func TestPostWriteFailureLeavesNoResidue(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 3)
	cold := filepath.Join(dir, "cold")

	// First rotation succeeds and seals the range.
	sealed, err := RotateSegment(hot, cold)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}

	// Rebuild the SAME range in the hot file, so the second rotation targets a
	// name that already exists.
	if err := os.Remove(hot); err != nil {
		t.Fatalf("remove hot: %v", err)
	}
	writeSpine(t, hot, 3)

	before, err := os.ReadDir(cold)
	if err != nil {
		t.Fatalf("read cold before: %v", err)
	}
	hotBefore, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot before: %v", err)
	}

	if _, err := RotateSegment(hot, cold); err == nil {
		t.Fatal("a second rotation overwrote an already-sealed segment; the archived " +
			"range would be replaced by a later one carrying the same name")
	}

	after, err := os.ReadDir(cold)
	if err != nil {
		t.Fatalf("read cold after: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("the failed rotation changed the cold tier from %d to %d file(s)",
			len(before), len(after))
	}

	// The already-sealed segment must be byte-unchanged, and the hot file whole.
	if _, err := ReadChainFile(sealed); err != nil {
		t.Errorf("the previously sealed segment no longer reads: %v", err)
	}
	hotAfter, err := os.ReadFile(hot)
	if err != nil {
		t.Fatalf("read hot after: %v", err)
	}
	if string(hotAfter) != string(hotBefore) {
		t.Errorf("the failed rotation truncated the hot file (%d -> %d bytes)",
			len(hotBefore), len(hotAfter))
	}
}

// TestRotateNeverOverwritesAnExistingSegment binds the exclusive create.
//
// A completed segment is mode 0400, so an attempt to rewrite one fails on
// permissions whether or not the open is exclusive — which is why the residue
// test above passes with O_EXCL removed. The case only O_EXCL rejects is a
// leftover WRITABLE file at the target name: the debris of a run interrupted
// between create and chmod. Without exclusivity that file is silently truncated
// and replaced, so a crashed rotation's partial output is overwritten by a
// second attempt with no record that either happened.
func TestRotateNeverOverwritesAnExistingSegment(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 3)

	cold := filepath.Join(dir, "cold")
	if err := os.MkdirAll(cold, 0o700); err != nil {
		t.Fatalf("mkdir cold: %v", err)
	}

	// The name RotateSegment will choose for this range, planted as writable
	// debris carrying content that is not the segment.
	debris := filepath.Join(cold, "control.00000000000000000001-00000000000000000003.jsonl")
	const marker = "interrupted-run-debris\n"
	if err := os.WriteFile(debris, []byte(marker), 0o600); err != nil {
		t.Fatalf("plant debris: %v", err)
	}

	if _, err := RotateSegment(hot, cold); err == nil {
		t.Fatal("rotation overwrote a pre-existing file at the segment name")
	}

	got, err := os.ReadFile(debris)
	if err != nil {
		t.Fatalf("read debris after: %v", err)
	}
	if string(got) != marker {
		t.Errorf("the pre-existing file was replaced (now %d bytes); a crashed "+
			"rotation's output is overwritten with no record that it existed", len(got))
	}
}

// TestRotatedSegmentIsReadOnly pins the sealed file's mode. A segment is
// finished; leaving it writable invites an append that no head covers, since
// the head was computed at seal time.
func TestRotatedSegmentIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 2)

	sealed, err := RotateSegment(hot, filepath.Join(dir, "cold"))
	if err != nil {
		t.Fatalf("RotateSegment: %v", err)
	}

	info, err := os.Stat(sealed)
	if err != nil {
		t.Fatalf("stat sealed: %v", err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("the sealed segment is mode %v, which is writable; an append after "+
			"sealing is covered by no head", info.Mode().Perm())
	}
}

// TestRotateLeavesTheHotFileResumable is what makes the next write link. After
// rotation the hot file must be empty but its TIP must come from the sealed
// segment, or the resumed sink restarts at genesis and the seam breaks.
func TestRotateLeavesTheHotFileResumable(t *testing.T) {
	dir := t.TempDir()
	hot := filepath.Join(dir, "audit.ocsf.jsonl")
	writeSpine(t, hot, 3)

	sealed, err := RotateSegment(hot, filepath.Join(dir, "cold"))
	if err != nil {
		t.Fatalf("RotateSegment: %v", err)
	}

	sealedEnvs, err := ReadChainFile(sealed)
	if err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	tail := sealedEnvs[len(sealedEnvs)-1]

	tip, err := ResumeTipAfterRotation(hot, sealed)
	if err != nil {
		t.Fatalf("ResumeTipAfterRotation: %v", err)
	}
	if tip.Fresh {
		t.Error("the tip after rotation reports Fresh; the resumed sink would restart " +
			"at genesis and the seam would break")
	}
	if tip.LastSeq != tail.Sequence || tip.PriorTip != tail.Hash {
		t.Errorf("tip is seq=%d prior=%s, the sealed tail is seq=%d hash=%s",
			tip.LastSeq, tip.PriorTip, tail.Sequence, tail.Hash)
	}
}
