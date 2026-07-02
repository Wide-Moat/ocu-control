// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkeyset

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// readKeySet drives a re-read of the written artifact into the published wire types
// so a test can assert per-record field values on WriteKeySet's ACTUAL output.
func readKeySet(t *testing.T, path string) keySetDoc {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read keyset: %v", err)
	}
	var doc keySetDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal keyset: %v", err)
	}
	return doc
}

// TestWriteKeySetProjectsPerRecordFieldValues proves WriteKeySet copies each record's
// OWN tenant, deployment, and key_id into the output — a faithful projection, not a
// constant. The existing frozen-shape test asserts these fields are PRESENT, and the
// golden byte-compares against fixtures that all use the same tenant-a / deploy-1
// literals, so a mutation that hardcoded the golden's constant (or read the wrong
// field) would ship green. This drives a record with DISTINCT values and asserts the
// output carries exactly them, so a constant-emission or field-swap mutation goes RED.
func TestWriteKeySetProjectsPerRecordFieldValues(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	// Values distinct from every existing fixture/golden literal, and distinct from
	// each OTHER so a tenant↔deployment swap is also caught.
	rec := realShapeRecord()
	rec.KeyID = "kid-fidelity-unique-9f3a"
	rec.Tenant = "tenant-fidelity-XYZ"
	rec.Deployment = "deploy-fidelity-QRS"

	if err := WriteKeySet(path, []mcpkey.Record{rec}, now); err != nil {
		t.Fatalf("WriteKeySet: %v", err)
	}

	doc := readKeySet(t, path)
	if len(doc.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(doc.Records))
	}
	got := doc.Records[0]
	if got.KeyID != rec.KeyID {
		t.Errorf("key_id = %q, want %q (the output must carry the record's own key_id)", got.KeyID, rec.KeyID)
	}
	if got.Tenant != rec.Tenant {
		t.Errorf("tenant = %q, want %q (the output must carry the record's own tenant, not a constant)", got.Tenant, rec.Tenant)
	}
	if got.Deployment != rec.Deployment {
		t.Errorf("deployment = %q, want %q (the output must carry the record's own deployment, not a constant or the tenant)", got.Deployment, rec.Deployment)
	}
	// The hash/salt hex must reflect THIS record's bytes, not a fixture constant.
	if got.KeyHash != hex.EncodeToString(rec.KeyHash) {
		t.Errorf("key_hash = %q, want the hex of the record's own KeyHash", got.KeyHash)
	}
	if got.Salt != hex.EncodeToString(rec.Salt) {
		t.Errorf("salt = %q, want the hex of the record's own Salt", got.Salt)
	}
}

// TestWriteKeySetPreservesPriorFileOnFault proves the atomic temp+rename write does not
// destroy an existing artifact when the rewrite faults: the OLD complete file survives.
// The existing fault tests only assert "no NEW file" on a fresh temp dir with no prior
// destination, so the preservation property (the whole point of temp+rename) was
// unproven — a regression that unlinked or truncated the destination before the temp
// write would not be caught. This seeds a valid prior artifact, faults the rewrite, and
// asserts the prior bytes are intact.
func TestWriteKeySetPreservesPriorFileOnFault(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	// Seed a valid prior artifact.
	if err := WriteKeySet(path, []mcpkey.Record{realShapeRecord()}, now); err != nil {
		t.Fatalf("seed WriteKeySet: %v", err)
	}
	prior, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read prior: %v", err)
	}

	// Fault the rewrite by making the destination directory unwritable so the temp
	// file cannot be created there. The prior file must remain byte-intact.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	writeErr := WriteKeySet(path, []mcpkey.Record{realShapeRecord()}, now)
	_ = os.Chmod(dir, 0o700)

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the prior artifact was destroyed by the rewrite attempt: %v", err)
	}
	if writeErr != nil {
		// The rewrite faulted (the expected path on most uids): the prior file must be
		// byte-intact — temp+rename never touches the destination until the final rename.
		if string(after) != string(prior) {
			t.Errorf("a FAULTED rewrite changed the prior artifact; temp+rename must leave the destination intact until the final rename.\nprior len=%d, after len=%d", len(prior), len(after))
		}
		return
	}
	// The rewrite did NOT fault (e.g. root in CI can write a 0500 dir): the file is a
	// fresh valid write, which must still parse as a well-formed keyset — never a
	// partial/corrupt file.
	if doc := readKeySet(t, path); len(doc.Records) != 1 {
		t.Errorf("after a successful rewrite the artifact has %d records, want 1 (not a partial write)", len(doc.Records))
	}
}

// TestWriteKeySetShortSaltEmitsSchemaInvalidSalt documents that WriteKeySet does NOT
// enforce the ≥16-hex (≥8-byte) salt floor — it hex-encodes whatever the record
// carries; the floor lives at construction (mcpkey.validateSalt), not in the writer. If
// a short-salt record reached WriteKeySet, the emitted salt would violate the frozen
// schema's ^[0-9a-f]{16,}$ pattern. This pins that observable: the writer's salt output
// is exactly the hex of the input, so a short input yields a short (schema-invalid) salt
// — a boundary the in-package suite otherwise never exercises (all fixtures use a
// 32-byte salt). It is a documentation/guard test, not a claim the writer sanitizes.
func TestWriteKeySetShortSaltEmitsSchemaInvalidSalt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	rec := realShapeRecord()
	rec.Salt = []byte{0x21, 0x22, 0x23, 0x24} // 4 bytes -> 8 hex chars, below the ≥16 floor

	if err := WriteKeySet(path, []mcpkey.Record{rec}, now); err != nil {
		t.Fatalf("WriteKeySet: %v", err)
	}
	doc := readKeySet(t, path)
	if len(doc.Records) != 1 {
		t.Fatalf("got %d records, want 1", len(doc.Records))
	}
	salt := doc.Records[0].Salt

	// The writer emits exactly the hex of the input salt — 8 chars here.
	if salt != hex.EncodeToString(rec.Salt) {
		t.Fatalf("salt = %q, want the hex of the input (the writer does not sanitize length)", salt)
	}
	// And that output does NOT satisfy the frozen ≥16-hex floor: this is the gap the
	// finding names — a short salt reaching the writer produces a schema-invalid
	// artifact, caught downstream by the schema, never by the writer.
	frozenSaltPattern := regexp.MustCompile(`^[0-9a-f]{16,}$`)
	if frozenSaltPattern.MatchString(salt) {
		t.Fatalf("a 4-byte salt unexpectedly satisfied the ≥16-hex floor (%q); the fixture drifted", salt)
	}
}
