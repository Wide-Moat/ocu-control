// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// writeAuditFile emits n privileged records through a real chain sink over a FileSink
// at path, producing a valid OCSF audit file for the verify tests.
func writeAuditFile(t *testing.T, path string, n int) {
	t.Helper()
	fs, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	sink := ocsf.NewChainSink(state.SystemClock(), fs, "control")
	for i := 0; i < n; i++ {
		if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k"}); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Test_AuditVerify_ValidChainOK proves `occ audit verify --file <valid>` reports OK and
// returns nil for an intact hash-chain, printing the verified event count.
func Test_AuditVerify_ValidChainOK(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, path, 3)

	var out bytes.Buffer
	err := run(context.Background(), []string{"audit", "verify", "--file", path}, &out, unixHTTPClient)
	if err != nil {
		t.Fatalf("occ audit verify on a valid chain = %v, want nil", err)
	}
	if !strings.Contains(out.String(), "audit chain OK") || !strings.Contains(out.String(), "3 events") {
		t.Fatalf("verify output %q does not confirm 3 verified events", out.String())
	}
}

// Test_AuditVerify_TamperedChainFails proves `occ audit verify` returns a non-nil error
// on a mutated event — the on-demand tamper-evidence check catches a byte flip, exactly
// as the daemon's boot verifier does.
func Test_AuditVerify_TamperedChainFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, path, 2)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"invoked_by":"operator"`), []byte(`"invoked_by":"0perator"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper produced no change; the fixture shape drifted")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	var out bytes.Buffer
	err = run(context.Background(), []string{"audit", "verify", "--file", path}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("occ audit verify on a tampered chain = nil; the verify must catch a mutated event")
	}
	if !strings.Contains(err.Error(), "INVALID") {
		t.Fatalf("verify error %q does not report the chain as INVALID", err)
	}
}

// Test_AuditVerify_MissingFileFlag proves the verb requires --file and returns a
// usageError naming it.
func Test_AuditVerify_MissingFileFlag(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"audit", "verify"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("occ audit verify with no --file = nil, want a usageError")
	}
	var ue usageError
	if !isUsageError(err, &ue) {
		t.Fatalf("error %T (%v) is not a usageError", err, err)
	}
}

// Test_AuditVerify_UnknownVerb proves an unknown audit verb is a usageError.
func Test_AuditVerify_UnknownVerb(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"audit", "bogus"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("occ audit bogus = nil, want a usageError")
	}
	if !strings.Contains(err.Error(), "unknown audit verb") {
		t.Fatalf("error %q does not name 'unknown audit verb'", err)
	}
}
