// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// TestReadChainFile covers the whole-file envelope reader used by the boot-time and
// occ-verb ValidateChain callers: an absent file is an empty chain; a valid file reads
// every envelope; a malformed line is a hard error (a corrupt audit file is a tamper
// signal, not something to skip).
func TestReadChainFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Absent file → empty chain, no error.
	envs, err := ocsf.ReadChainFile(filepath.Join(dir, "absent.jsonl"))
	if err != nil || len(envs) != 0 {
		t.Fatalf("ReadChainFile(absent) = (%v, %v), want (empty, nil)", envs, err)
	}

	// A valid file with two events reads back both envelopes.
	path := filepath.Join(dir, "audit.jsonl")
	fs, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	sink := ocsf.NewChainSink(newClock(), fs, "control")
	for i := 0; i < 2; i++ {
		if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k"}); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	_ = fs.Close()
	envs, err = ocsf.ReadChainFile(path)
	if err != nil {
		t.Fatalf("ReadChainFile(valid) = %v", err)
	}
	if len(envs) != 2 {
		t.Fatalf("ReadChainFile read %d envelopes, want 2", len(envs))
	}

	// A malformed line is a hard error.
	bad := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(bad, []byte("not json\n"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, err := ocsf.ReadChainFile(bad); err == nil {
		t.Fatal("ReadChainFile on a malformed line = nil, want an error (a corrupt audit file is a tamper signal)")
	}
}

// TestReadTipDecoupledVariants covers the parseValidTip error branches ReadTip surfaces
// as ErrTipDecoupled: a non-JSON tail, a zero-sequence tail, and a hash-mismatch tail.
func TestReadTipDecoupledVariants(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	cases := map[string]string{
		"non-json tail":     "{not json\n",
		"zero-sequence":     `{"source":"control","sequence":0,"prior_hash":"00","hash":"00","event":{}}` + "\n",
		"hash-mismatch":     `{"source":"control","sequence":1,"prior_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"deadbeef","event":{}}` + "\n",
		"unrecomputable-ph": `{"source":"control","sequence":1,"prior_hash":"zz","hash":"00","event":{}}` + "\n",
	}
	for name, line := range cases {
		name, line := name, line
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, name+".jsonl")
			if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := ocsf.ReadTip(path); !errors.Is(err, ocsf.ErrTipDecoupled) {
				t.Fatalf("ReadTip(%s) = %v, want ErrTipDecoupled", name, err)
			}
		})
	}
}

// TestEmitChainBreakEmptyTipCoerced covers buildChainBreakEvent's empty-tip coercion
// (an empty observedTip becomes the "unreadable" sentinel) so the marker still carries
// a non-empty observed_prior_tip and ValidateChain accepts it.
func TestEmitChainBreakEmptyTipCoerced(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	if err := sink.EmitChainBreak(context.Background(), ""); err != nil {
		t.Fatalf("EmitChainBreak(empty) = %v", err)
	}
	if err := ocsf.ValidateChain(w.envs); err != nil {
		t.Fatalf("ValidateChain after an empty-tip chain-break = %v; the empty tip must be coerced to the sentinel, not left empty", err)
	}
}

// TestEmitChainBreakCancelledContext covers the fail-closed context guard on
// EmitChainBreak: a cancelled context denies before any work.
func TestEmitChainBreakCancelledContext(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.EmitChainBreak(ctx, "x"); !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("EmitChainBreak(cancelled) = %v, want ErrAuditWriteFailed", err)
	}
}
