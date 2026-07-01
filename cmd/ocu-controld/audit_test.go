// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
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
