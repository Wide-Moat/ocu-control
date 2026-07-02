// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Test_buildAuditWriter_RealPathIsDurable proves a real -audit-sink path resolves to
// a durable writer that actually appends: a write produces a line on disk and Close
// flushes cleanly. This is the structural fix — a named path is never silently
// discarded; it is backed by the fsync-on-write FileSink.
func Test_buildAuditWriter_RealPathIsDurable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	w, err := buildAuditWriter(path)
	if err != nil {
		t.Fatalf("buildAuditWriter(%q) = %v, want a durable writer", path, err)
	}
	t.Cleanup(func() { _ = w.Close() })

	if err := w.Write(context.Background(), ocsf.ChainEnvelope{Source: "control", Sequence: 1}); err != nil {
		t.Fatalf("durable writer Write = %v, want nil", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("durable writer Close = %v, want nil", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("durable writer left no file at %q: %v", path, statErr)
	}
}

// Test_buildAuditWriter_NoneSelectsNullWriter proves the explicit =none/=null opt-out
// resolves to a non-durable writer whose Write and Close never fail and whose Write
// persists nothing — the only sanctioned way to run without a durable trail. Both
// spellings, case-insensitively, must select it.
func Test_buildAuditWriter_NoneSelectsNullWriter(t *testing.T) {
	t.Parallel()
	for _, sink := range []string{"none", "null", "NONE", "Null"} {
		sink := sink
		t.Run(sink, func(t *testing.T) {
			t.Parallel()
			w, err := buildAuditWriter(sink)
			if err != nil {
				t.Fatalf("buildAuditWriter(%q) = %v, want the null writer", sink, err)
			}
			if err := w.Write(context.Background(), ocsf.ChainEnvelope{Source: "control", Sequence: 1}); err != nil {
				t.Fatalf("null writer Write = %v, want nil (never denies)", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("null writer Close = %v, want nil (no-op)", err)
			}
		})
	}
}

// Test_buildAuditWriter_UnwritablePathFailsClosed proves an unopenable -audit-sink
// path is an error, so serve() turns it into a fail-closed boot abort rather than
// booting with a discarded trail.
func Test_buildAuditWriter_UnwritablePathFailsClosed(t *testing.T) {
	t.Parallel()
	bad := filepath.Join(t.TempDir(), "no-such-dir", "audit.ocsf.jsonl")
	if _, err := buildAuditWriter(bad); err == nil {
		t.Fatal("buildAuditWriter on an uncreatable path = nil, want an error (fail-closed boot abort)")
	}
}

// bootEmit binds a resumed chain sink over path (as buildResumedChainSink does at
// boot), emits n privileged records through it, and closes the writer — one simulated
// daemon boot through the real boot wiring.
func bootEmit(t *testing.T, path string, n int) {
	t.Helper()
	w, err := buildAuditWriter(path)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	sink, err := buildResumedChainSink(context.Background(), state.SystemClock(), w, path)
	if err != nil {
		t.Fatalf("buildResumedChainSink: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k"}); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Test_buildResumedChainSink_ContinuesSpineAcrossBoots proves the boot wiring resumes
// the chain: two boots over the same file produce one continuous spine that
// verifyAuditChainFile (the shipped ValidateChain caller) accepts. Before the fix a
// fresh sink re-anchored at genesis each boot and the file failed the chain.
func Test_buildResumedChainSink_ContinuesSpineAcrossBoots(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")

	bootEmit(t, path, 2) // boot 1: sequences 1, 2
	bootEmit(t, path, 2) // boot 2 (restart): continues at 3, 4

	if err := verifyAuditChainFile(path); err != nil {
		t.Fatalf("verifyAuditChainFile after two boots = %v; the restart must continue one spine, not re-anchor", err)
	}
}

// Test_buildResumedChainSink_DecoupledTailRecordsChainBreak proves a boot over a file
// whose tail is torn records an explicit chain-break marker and still produces a valid
// spine (the marked re-anchor). The silent-re-anchor alternative would leave the file
// failing verifyAuditChainFile.
func Test_buildResumedChainSink_DecoupledTailRecordsChainBreak(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")

	bootEmit(t, path, 1) // one valid envelope
	// Append a torn/garbage tail line (an unparseable-as-consistent envelope).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open to append garbage: %v", err)
	}
	if _, err := f.WriteString(`{"source":"control","sequence":2,"prior_hash":"00","hash":"deadbeef","event":{}}` + "\n"); err != nil {
		t.Fatalf("append garbage: %v", err)
	}
	_ = f.Close()

	// A boot over the torn file: verifyAuditChainFile runs first and rejects the torn
	// tail, so the boot aborts BEFORE appending — the file is already broken. This is
	// the fail-closed guard: a boot never appends onto a spine that already fails.
	w, err := buildAuditWriter(path)
	if err != nil {
		t.Fatalf("buildAuditWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	_, err = buildResumedChainSink(context.Background(), state.SystemClock(), w, path)
	if err == nil {
		t.Fatal("buildResumedChainSink over a torn file = nil; a file that already fails the chain must abort the boot")
	}
}

// Test_verifyAuditChainFile_RejectsTamper proves the shipped boot verifier catches a
// mutated event: flipping a byte in a committed envelope's event makes
// verifyAuditChainFile fail, so a boot over a tampered file aborts. This is the whole
// point of wiring ValidateChain into a shipped caller — the tamper-evidence actually runs.
func Test_verifyAuditChainFile_RejectsTamper(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	bootEmit(t, path, 2)

	// Mutate a byte inside the first record's event payload.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Replace the first "operator" channel value with "0perator" (same length), a
	// single-byte change to the hashed event bytes.
	tampered := bytes.Replace(raw, []byte(`"invoked_by":"operator"`), []byte(`"invoked_by":"0perator"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper produced no change; the test fixture shape drifted")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	if err := verifyAuditChainFile(path); err == nil {
		t.Fatal("verifyAuditChainFile on a tampered file = nil; the boot verifier must catch a mutated event")
	}
}
