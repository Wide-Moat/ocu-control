// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// bootAndEmit binds a resumed ChainSink over the file at path (reading its tip) and
// emits n privileged records, then closes the file — one simulated daemon boot.
func bootAndEmit(t *testing.T, path string, n int) {
	t.Helper()
	tip, err := ocsf.ReadTip(path)
	if err != nil {
		t.Fatalf("ReadTip: %v", err)
	}
	fs, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	sink := ocsf.ResumeChainSink(newClock(), fs, "control", tip)
	for i := 0; i < n; i++ {
		if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k", Reason: "r"}); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// readEnvelopes reads every JSON line of the audit file back into ChainEnvelopes.
func readEnvelopes(t *testing.T, path string) []ocsf.ChainEnvelope {
	t.Helper()
	var envs []ocsf.ChainEnvelope
	for _, ln := range readLines(t, path) {
		var e ocsf.ChainEnvelope
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		envs = append(envs, e)
	}
	return envs
}

// TestResumeKeepsOneContinuousSpineAcrossRestarts is the fix for the chain-restart
// break: two boots (a resumed ChainSink each time over the same file) must produce a
// single spine ValidateChain accepts — sequence strictly monotonic 1..N across the
// boot boundary, prior-hash unbroken. Contrast the pre-fix behaviour, where a fresh
// NewChainSink re-anchored at genesis and ValidateChain rejected the two-boot file.
func TestResumeKeepsOneContinuousSpineAcrossRestarts(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")

	bootAndEmit(t, path, 2) // boot 1: sequences 1, 2
	bootAndEmit(t, path, 2) // boot 2 (restart): must continue at 3, 4

	envs := readEnvelopes(t, path)
	if len(envs) != 4 {
		t.Fatalf("want 4 envelopes across two boots, got %d", len(envs))
	}
	for i, e := range envs {
		if e.Sequence != uint64(i+1) {
			t.Errorf("envelope %d sequence = %d, want %d (spine must stay monotonic across the restart)", i, e.Sequence, i+1)
		}
	}
	if err := ocsf.ValidateChain(envs); err != nil {
		t.Fatalf("ValidateChain rejected the two-boot spine: %v; the restart must continue one continuous chain, not re-anchor", err)
	}
}

// TestReadTipEmptyAndAbsentAreGenesis proves an absent or empty file resumes at
// genesis LEGITIMATELY (Fresh=true), so a first boot starts the spine at sequence 1.
func TestReadTipEmptyAndAbsentAreGenesis(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Absent file.
	tip, err := ocsf.ReadTip(filepath.Join(dir, "absent.jsonl"))
	if err != nil {
		t.Fatalf("ReadTip(absent): %v", err)
	}
	if !tip.Fresh || tip.LastSeq != 0 {
		t.Errorf("ReadTip(absent) = %+v, want genesis (Fresh, LastSeq 0)", tip)
	}

	// Empty file.
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	tip, err = ocsf.ReadTip(empty)
	if err != nil {
		t.Fatalf("ReadTip(empty): %v", err)
	}
	if !tip.Fresh || tip.LastSeq != 0 {
		t.Errorf("ReadTip(empty) = %+v, want genesis (Fresh, LastSeq 0)", tip)
	}
}

// TestReadTipDecoupledTailIsAnError proves a non-empty file whose last line is not a
// valid, hash-consistent ChainEnvelope is reported as ErrTipDecoupled — NOT silently
// resumed at genesis. This is the guard against a torn last write or a truncated tail
// masquerading as a fresh spine (the boot path turns this into an explicit chain-break
// record rather than a silent re-anchor).
func TestReadTipDecoupledTailIsAnError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// A valid first line followed by a torn/garbage last line.
	path := filepath.Join(dir, "torn.jsonl")
	bootAndEmit(t, path, 1) // one valid envelope
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open to append garbage: %v", err)
	}
	if _, err := f.WriteString(`{"source":"control","sequence":2,"prior_hash":"00","hash":"deadbeef","event":{}}` + "\n"); err != nil {
		t.Fatalf("append garbage: %v", err)
	}
	_ = f.Close()

	_, err = ocsf.ReadTip(path)
	if !errors.Is(err, ocsf.ErrTipDecoupled) {
		t.Fatalf("ReadTip on a decoupled tail = %v, want ErrTipDecoupled (a torn tail must never silently re-anchor at genesis)", err)
	}
}
