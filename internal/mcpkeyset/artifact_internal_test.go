// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mcpkeyset — internal test file. This file is compiled in the same
// package so it can reach the unexported writeAtomic + createTemp fault-inject
// seam, mirroring jwks/artifact_internal_test.go exactly.
package mcpkeyset

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// ---- helpers -----------------------------------------------------------------

// activeRecord returns a single active, non-expired Record for use in atomic
// write tests (the set must be non-empty so we reach the filesystem).
func activeRecord() mcpkey.Record {
	return mcpkey.Record{
		KeyID:      "kid-test-001",
		KeyHash:    []byte("hashbytes"),
		Salt:       []byte("saltbytes"),
		Tenant:     "tenant-a",
		Deployment: "deploy-1",
		Status:     mcpkey.StatusActive,
		CreatedAt:  time.Now(),
	}
}

// revokedRecord returns a revoked Record for use in revoked-omission tests.
func revokedRecord() mcpkey.Record {
	r := activeRecord()
	r.KeyID = "kid-revoked-001"
	r.Status = mcpkey.StatusRevoked
	return r
}

// expiredRecord returns an expired active Record for use in expired-omission tests.
func expiredRecord() mcpkey.Record {
	r := activeRecord()
	r.KeyID = "kid-expired-001"
	r.ExpiresAt = time.Now().Add(-time.Hour)
	return r
}

// realShapeRecord returns an active Record whose KeyHash is a full 32-byte
// (sha256-width) value and Salt is a 32-byte value, so the projected hex strings
// match the frozen A2 patterns (^[0-9a-f]{64}$ for key_hash, ^[0-9a-f]{16,}$ for
// salt). The activeRecord() helper above uses short literal bytes that suffice for
// the omission/atomic tests but not for the frozen-shape assertion.
func realShapeRecord() mcpkey.Record {
	hash := make([]byte, 32)
	salt := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	for i := range salt {
		salt[i] = byte(i + 33)
	}
	return mcpkey.Record{
		KeyID:      "kid-real-001",
		KeyHash:    hash,
		Salt:       salt,
		Tenant:     "tenant-a",
		Deployment: "deploy-1",
		Status:     mcpkey.StatusActive,
		CreatedAt:  time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	}
}

// ---- fakeTempFile seam -------------------------------------------------------

// fakeTempFile wraps a real *os.File while letting a test force any one method
// to fail or short-write. It is the fault-injection vehicle for writeAtomic's
// os.File error branches, mirroring jwks/artifact_internal_test.go exactly.
type fakeTempFile struct {
	real       *os.File
	chmodErr   error
	writeErr   error
	shortWrite bool // report one fewer byte than written
	syncErr    error
	closeErr   error
}

func (f *fakeTempFile) Name() string { return f.real.Name() }

func (f *fakeTempFile) Chmod(m os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.real.Chmod(m)
}

func (f *fakeTempFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	n, err := f.real.Write(p)
	if f.shortWrite && n > 0 {
		return n - 1, err // report a short write while the data is intact
	}
	return n, err
}

func (f *fakeTempFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.real.Sync()
}

func (f *fakeTempFile) Close() error {
	if f.closeErr != nil {
		_ = f.real.Close()
		return f.closeErr
	}
	return f.real.Close()
}

// withFakeTemp installs a createTemp override that returns a fakeTempFile
// configured by mut, and restores the original on cleanup. Mirrors
// jwks/artifact_internal_test.go#withFakeTemp.
func withFakeTemp(t *testing.T, mut func(f *fakeTempFile)) {
	t.Helper()
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	createTemp = func(dir, pattern string) (tempFile, error) {
		real, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		f := &fakeTempFile{real: real}
		mut(f)
		return f, nil
	}
}

// ---- WriteKeySet tests -------------------------------------------------------

// TestWriteKeySetAtomic proves that a successful WriteKeySet call lands a
// well-formed {"version":1,...} document at the target path containing only the
// active, non-expired record subset.
func TestWriteKeySetAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	records := []mcpkey.Record{activeRecord(), revokedRecord(), expiredRecord()}
	if err := WriteKeySet(path, records, now); err != nil {
		t.Fatalf("WriteKeySet returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Must be a single well-formed JSON object with version:1.
	var doc struct {
		Version int             `json:"version"`
		Records json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal keyset: %v", err)
	}
	if doc.Version != 1 {
		t.Fatalf("got version=%d; want 1", doc.Version)
	}
	// The document must exist and be non-empty.
	if len(data) == 0 {
		t.Fatal("WriteKeySet wrote an empty file")
	}
}

// TestWriteKeySetFrozenA2Shape is the RED-when-neutered proof that the published
// record matches the FROZEN Artifact-2 hashed-key-set contract: key_hash is
// lowercase-hex matching ^[0-9a-f]{64}$ (NOT base64 — a []byte marshals to base64
// by default, which this test would catch), salt is ^[0-9a-f]{16,}$, status is the
// literal "active", created_at is RFC3339, and expires_at is present only for an
// expiring key and omitted for a non-expiring one. It also asserts NO plaintext
// secret and NO extra fields leak into the record.
func TestWriteKeySetFrozenA2Shape(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	nonExpiring := realShapeRecord() // zero ExpiresAt → non-expiring
	expiring := realShapeRecord()
	expiring.KeyID = "kid-real-002"
	expiring.ExpiresAt = now.Add(24 * time.Hour) // future → still active

	if err := WriteKeySet(path, []mcpkey.Record{nonExpiring, expiring}, now); err != nil {
		t.Fatalf("WriteKeySet: %v", err)
	}

	var doc struct {
		Version int              `json:"version"`
		Records []map[string]any `json:"records"`
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Version != 1 {
		t.Fatalf("version = %d; want 1 (frozen const)", doc.Version)
	}
	if len(doc.Records) != 2 {
		t.Fatalf("got %d records; want 2", len(doc.Records))
	}

	hexHash := regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexSalt := regexp.MustCompile(`^[0-9a-f]{16,}$`)
	rfc3339 := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)

	// The frozen required field set: key_id, key_hash, salt, tenant, deployment,
	// status, created_at. expires_at is optional. NO other field may appear.
	allowed := map[string]bool{
		"key_id": true, "key_hash": true, "salt": true, "tenant": true,
		"deployment": true, "status": true, "expires_at": true, "created_at": true,
	}
	required := []string{"key_id", "key_hash", "salt", "tenant", "deployment", "status", "created_at"}

	for i, rec := range doc.Records {
		for k := range rec {
			if !allowed[k] {
				t.Errorf("record[%d] has forbidden field %q (additionalProperties:false)", i, k)
			}
		}
		for _, k := range required {
			if _, ok := rec[k]; !ok {
				t.Errorf("record[%d] missing required field %q", i, k)
			}
		}
		if kh, _ := rec["key_hash"].(string); !hexHash.MatchString(kh) {
			t.Errorf("record[%d] key_hash %q is not 64-char lowercase hex (base64 leak?)", i, kh)
		}
		if s, _ := rec["salt"].(string); !hexSalt.MatchString(s) {
			t.Errorf("record[%d] salt %q is not lowercase hex ≥16 chars", i, s)
		}
		if st, _ := rec["status"].(string); st != "active" {
			t.Errorf("record[%d] status = %q; want active (only active records are published)", i, st)
		}
		if ca, _ := rec["created_at"].(string); !rfc3339.MatchString(ca) {
			t.Errorf("record[%d] created_at %q is not RFC3339", i, ca)
		}
	}

	// The non-expiring record (index 0) must OMIT expires_at; the expiring one
	// (index 1) must carry a RFC3339 expires_at.
	if _, present := doc.Records[0]["expires_at"]; present {
		t.Errorf("non-expiring record carries expires_at; want it omitted")
	}
	if ea, _ := doc.Records[1]["expires_at"].(string); !rfc3339.MatchString(ea) {
		t.Errorf("expiring record expires_at %q is not RFC3339", ea)
	}

	// No plaintext secret marker anywhere in the artifact bytes.
	if strings.Contains(string(data), "sk-ocu-") {
		t.Fatal("plaintext sk-ocu- marker found in the published keyset")
	}
}

// TestWriteKeySetEmptyFailsClosed proves that WriteKeySet returns ErrEmptyKeySet
// when the active+non-expired subset is empty, and writes NOTHING to disk.
func TestWriteKeySetEmptyFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	// Only revoked and expired records — active subset is empty.
	err := WriteKeySet(path, []mcpkey.Record{revokedRecord(), expiredRecord()}, now)
	if !errors.Is(err, ErrEmptyKeySet) {
		t.Fatalf("WriteKeySet over an all-revoked/expired set returned %v; want ErrEmptyKeySet", err)
	}

	// No file must have been written.
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("WriteKeySet ErrEmptyKeySet left a file at path (stat=%v)", statErr)
	}
}

// TestWriteKeySetNilFailsClosed proves the nil/empty-slice path also triggers
// ErrEmptyKeySet with no filesystem touch.
func TestWriteKeySetNilFailsClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	if err := WriteKeySet(path, nil, now); !errors.Is(err, ErrEmptyKeySet) {
		t.Fatalf("WriteKeySet(nil) returned %v; want ErrEmptyKeySet", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("WriteKeySet nil left a file (stat=%v)", statErr)
	}
}

// TestWriteKeySetRevokedOmitted proves that revoked records are absent from the
// written keyset (a revoked key must not survive in the published set).
func TestWriteKeySetRevokedOmitted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	active := activeRecord()
	revoked := revokedRecord()
	if err := WriteKeySet(path, []mcpkey.Record{active, revoked}, now); err != nil {
		t.Fatalf("WriteKeySet: %v", err)
	}

	data, _ := os.ReadFile(path)
	// The revoked key_id must NOT appear in the output.
	if strings.Contains(string(data), revoked.KeyID) {
		t.Fatalf("revoked KeyID %q found in keyset; must be omitted (fail-closed)", revoked.KeyID)
	}
	// The active key_id must appear.
	if !strings.Contains(string(data), active.KeyID) {
		t.Fatalf("active KeyID %q missing from keyset", active.KeyID)
	}
}

// TestWriteKeySetExpiredOmitted proves that expired records are omitted just as
// revoked ones are (fail-closed on the expiry dimension).
func TestWriteKeySetExpiredOmitted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyset.json")
	now := time.Now()

	active := activeRecord()
	expired := expiredRecord()
	if err := WriteKeySet(path, []mcpkey.Record{active, expired}, now); err != nil {
		t.Fatalf("WriteKeySet: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), expired.KeyID) {
		t.Fatalf("expired KeyID %q found in keyset; must be omitted", expired.KeyID)
	}
}

// TestWriteKeySetNoListener is an import-graph guard: the mcpkeyset package must
// contain no net.Listener or net/http import — disk syscalls only (NFR-SEC-52,
// two-listener invariant untouched).
func TestWriteKeySetNoListener(t *testing.T) {
	t.Parallel()
	// Walk the source files of this package and assert no net/http or net.Listener.
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	forbidden := []string{`"net/http"`, `"net"`, `net.Listener`}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue // test files may import whatever they need
		}
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, marker := range forbidden {
			if strings.Contains(string(content), marker) {
				t.Errorf("production file %s imports %q — no listener allowed (NFR-SEC-52)", f, marker)
			}
		}
	}
}

// TestWriteKeySetAtomicInjectedFaults drives every os.File error branch of
// writeAtomic through the createTemp fault-inject seam. Mirrors
// jwks/artifact_internal_test.go#TestWriteAtomicInjectedFaults.
func TestWriteKeySetAtomicInjectedFaults(t *testing.T) {
	boom := errors.New("injected fault")
	now := time.Now()
	records := []mcpkey.Record{activeRecord()}

	cases := []struct {
		name    string
		mut     func(f *fakeTempFile)
		wantSub string
	}{
		{"chmod", func(f *fakeTempFile) { f.chmodErr = boom }, "chmod temp"},
		{"write", func(f *fakeTempFile) { f.writeErr = boom }, "write temp"},
		{"short write", func(f *fakeTempFile) { f.shortWrite = true }, "short write"},
		{"sync", func(f *fakeTempFile) { f.syncErr = boom }, "sync temp"},
		{"close", func(f *fakeTempFile) { f.closeErr = boom }, "close temp"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withFakeTemp(t, tc.mut)
			dir := t.TempDir()
			path := filepath.Join(dir, "keyset.json")
			err := WriteKeySet(path, records, now)
			if err == nil {
				t.Fatalf("WriteKeySet under an injected %s fault returned nil; want an error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("WriteKeySet %s error %q does not mention %q", tc.name, err, tc.wantSub)
			}
			// No destination file on a faulted write.
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s fault left a destination file (stat=%v); want none", tc.name, statErr)
			}
			// No leftover temp file.
			entries, rdErr := os.ReadDir(dir)
			if rdErr != nil {
				t.Fatalf("readdir: %v", rdErr)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".tmp-mcpkeyset-") {
					t.Fatalf("%s fault left a temp file %q; want cleaned up", tc.name, e.Name())
				}
			}
		})
	}
}

// TestWriteKeySetCreateTempFails proves the create-temp error branch.
func TestWriteKeySetCreateTempFails(t *testing.T) {
	t.Parallel()
	now := time.Now()
	// A path whose parent dir does not exist makes os.CreateTemp fail.
	path := filepath.Join(t.TempDir(), "no-such-subdir", "keyset.json")
	err := WriteKeySet(path, []mcpkey.Record{activeRecord()}, now)
	if err == nil {
		t.Fatal("WriteKeySet into a missing directory returned nil; want a create-temp error")
	}
	if !strings.Contains(err.Error(), "create temp") {
		t.Fatalf("error %q does not mention the create-temp step", err)
	}
}

// ---- WriteEntriesFile / LoadEntriesFile tests --------------------------------

// TestWriteEntriesFileMode proves the minimal-shelf hashed-entries file is
// written at mode 0600 (root-owned house pattern).
func TestWriteEntriesFileMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")

	records := []mcpkey.Record{activeRecord(), revokedRecord()}
	if err := WriteEntriesFile(path, records); err != nil {
		t.Fatalf("WriteEntriesFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode %04o; want 0600", got)
	}
}

// TestWriteEntriesFileSingleJSONObject proves the file is a SINGLE versioned
// JSON object {"version":1,"records":[…]}, NOT newline-delimited. A truncated
// read of a single JSON document fails closed (a parse error), never silently
// "fewer valid keys."
func TestWriteEntriesFileSingleJSONObject(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")

	records := []mcpkey.Record{activeRecord(), revokedRecord()}
	if err := WriteEntriesFile(path, records); err != nil {
		t.Fatalf("WriteEntriesFile: %v", err)
	}

	data, _ := os.ReadFile(path)
	var doc struct {
		Version int             `json:"version"`
		Records []mcpkey.Record `json:"records"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v — must be a single JSON object, not NDJSON", err)
	}
	if doc.Version != 1 {
		t.Fatalf("version=%d; want 1", doc.Version)
	}
	// Both records must appear (full at-rest set, not the active-only subset).
	if len(doc.Records) != 2 {
		t.Fatalf("got %d records; want 2 (full at-rest set)", len(doc.Records))
	}
}

// TestEntriesRoundTrip writes N records and reads them back; the same N records
// must be returned with the full record shape intact.
func TestEntriesRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")

	input := []mcpkey.Record{activeRecord(), revokedRecord(), expiredRecord()}
	if err := WriteEntriesFile(path, input); err != nil {
		t.Fatalf("WriteEntriesFile: %v", err)
	}

	// Must be readable at 0600 by the owner, which is the current test process.
	got, err := LoadEntriesFile(path)
	if err != nil {
		t.Fatalf("LoadEntriesFile: %v", err)
	}
	if len(got) != len(input) {
		t.Fatalf("round-trip: got %d records; want %d", len(got), len(input))
	}
	// Spot-check key fields survive round-trip.
	for i, r := range got {
		if r.KeyID != input[i].KeyID {
			t.Errorf("[%d] KeyID %q != %q", i, r.KeyID, input[i].KeyID)
		}
		if r.Status != input[i].Status {
			t.Errorf("[%d] Status %q != %q", i, r.Status, input[i].Status)
		}
	}
}

// TestLoadEntriesFilePostureGuard proves that LoadEntriesFile refuses a file
// whose permissions are looser than 0600 (a world/group-readable hashed-entries
// file is a store-disclosure surface even though it holds only hashes).
func TestLoadEntriesFilePostureGuard(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")

	// Write a valid file and then widen its permissions to simulate a posture failure.
	records := []mcpkey.Record{activeRecord()}
	if err := WriteEntriesFile(path, records); err != nil {
		t.Fatalf("WriteEntriesFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := LoadEntriesFile(path)
	if !errors.Is(err, ErrLoosePermissions) {
		t.Fatalf("LoadEntriesFile with 0644 returned %v; want ErrLoosePermissions", err)
	}
}

// TestEntriesAtomicInjectedFaults drives every writeAtomic fault branch for
// WriteEntriesFile, proving the old-complete file is preserved on any fault.
func TestEntriesAtomicInjectedFaults(t *testing.T) {
	boom := errors.New("injected fault")
	records := []mcpkey.Record{activeRecord()}

	cases := []struct {
		name    string
		mut     func(f *fakeTempFile)
		wantSub string
	}{
		{"chmod", func(f *fakeTempFile) { f.chmodErr = boom }, "chmod temp"},
		{"write", func(f *fakeTempFile) { f.writeErr = boom }, "write temp"},
		{"short write", func(f *fakeTempFile) { f.shortWrite = true }, "short write"},
		{"sync", func(f *fakeTempFile) { f.syncErr = boom }, "sync temp"},
		{"close", func(f *fakeTempFile) { f.closeErr = boom }, "close temp"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withFakeTemp(t, tc.mut)
			dir := t.TempDir()
			path := filepath.Join(dir, "entries.json")
			err := WriteEntriesFile(path, records)
			if err == nil {
				t.Fatalf("WriteEntriesFile under %s fault returned nil; want error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("WriteEntriesFile %s error %q missing %q", tc.name, err, tc.wantSub)
			}
			// No destination file on a faulted write.
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s fault left a destination file (stat=%v); want none", tc.name, statErr)
			}
		})
	}
}

// TestEntriesNoLeak proves that no plaintext "sk-ocu-" marker appears in the
// file bytes written by WriteEntriesFile (the plaintext secret is NEVER persisted,
// only the salted hash + salt).
func TestEntriesNoLeak(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "entries.json")

	r := activeRecord()
	// Simulate a worst-case where the key_hash bytes happen to match the sk-ocu- prefix
	// bytes literally — they won't, but we assert the file never contains the string.
	r.KeyHash = []byte("notaplaintextkey")
	if err := WriteEntriesFile(path, []mcpkey.Record{r}); err != nil {
		t.Fatalf("WriteEntriesFile: %v", err)
	}

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "sk-ocu-") {
		t.Fatal("plaintext 'sk-ocu-' found in entries file; must never be written")
	}
}
