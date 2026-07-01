// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// External test: pins the exact bytes WriteKeySet publishes for a fixed,
// production-shaped record set against the committed golden artifact. The
// golden is what CI ajv-validates against the vendored canon schema
// (contracts/mcp/mcp-key-set.schema.json), closing the byte-identity chain:
// WriteKeySet output == golden (this test) and golden ⊨ frozen A2 schema (CI).
package mcpkeyset_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/mcpkeyset"
)

var update = flag.Bool("update", false, "regenerate testdata/mcp-key-set.golden.json from WriteKeySet")

// seqBytes returns n bytes counting up from start — fixed, readable hex in the
// golden (0x01.. for the hash, 0x21.. for the salt, matching the canon schema's
// own examples, which were authored from this repo's frozen-shape pins).
func seqBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// TestWriteKeySetMatchesGolden renders a production-shaped record set (24-hex
// key_id, 64-hex salt and hash, RFC3339 UTC timestamps) plus one revoked and
// one expired record that MUST be omitted, and asserts the artifact bytes are
// exactly the committed golden. Regenerate deliberately with:
//
//	go test ./internal/mcpkeyset -run TestWriteKeySetMatchesGolden -update
func TestWriteKeySetMatchesGolden(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 30, 0, 0, time.UTC)
	minted := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	records := []mcpkey.Record{
		{
			KeyID:      "a1b2c3d4e5f6a7b8c9d0e1f2",
			KeyHash:    seqBytes(0x01, 32),
			Salt:       seqBytes(0x21, 32),
			Tenant:     "tenant-a",
			Deployment: "deploy-1",
			Status:     mcpkey.StatusActive,
			CreatedAt:  minted,
		},
		{
			KeyID:      "0011223344556677889900aa",
			KeyHash:    seqBytes(0x01, 32),
			Salt:       seqBytes(0x21, 32),
			Tenant:     "tenant-a",
			Deployment: "deploy-1",
			Status:     mcpkey.StatusActive,
			ExpiresAt:  time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC),
			CreatedAt:  minted,
		},
		// Revoked: must be omitted from the published set (fail-closed).
		{
			KeyID:      "ffeeddccbbaa998877665544",
			KeyHash:    seqBytes(0x01, 32),
			Salt:       seqBytes(0x21, 32),
			Tenant:     "tenant-a",
			Deployment: "deploy-1",
			Status:     mcpkey.StatusRevoked,
			CreatedAt:  minted,
		},
		// Expired relative to now: must be omitted from the published set.
		{
			KeyID:      "123456789abcdef012345678",
			KeyHash:    seqBytes(0x01, 32),
			Salt:       seqBytes(0x21, 32),
			Tenant:     "tenant-a",
			Deployment: "deploy-1",
			Status:     mcpkey.StatusActive,
			ExpiresAt:  time.Date(2026, 3, 1, 11, 0, 0, 0, time.UTC),
			CreatedAt:  minted,
		},
	}

	path := filepath.Join(t.TempDir(), "mcp-key-set.json")
	if err := mcpkeyset.WriteKeySet(path, records, now); err != nil {
		t.Fatalf("WriteKeySet: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}

	golden := filepath.Join("testdata", "mcp-key-set.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to regenerate deliberately): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("WriteKeySet output drifted from the golden artifact.\nA deliberate wire change must re-vendor the canon schema first, then regenerate with -update.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
