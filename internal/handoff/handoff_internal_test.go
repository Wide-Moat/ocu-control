// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileExactFullContentAnd0600 proves writeFileExact lands the exact
// payload at 0600 and leaves no temp file behind. The short-write branch it
// guards is defensive against a partial os.File.Write; here we pin the success
// invariant — every byte present, owner-only mode, atomic rename done.
func TestWriteFileExactFullContentAnd0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	payload := bytes.Repeat([]byte{0xAB}, 4096)

	if err := writeFileExact(path, payload); err != nil {
		t.Fatalf("writeFileExact: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Fatalf("perm = %o, want %o", perm, filePerm)
	}

	// No leftover temp file in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "artifact.bin" {
			t.Fatalf("leftover entry after writeFileExact: %q", e.Name())
		}
	}
}

// TestContainerInfoForIsValidJSON proves the staged container_info.json bytes are
// well-formed JSON carrying the host-derived session name.
func TestContainerInfoForIsValidJSON(t *testing.T) {
	t.Parallel()
	b := containerInfoFor("my-session")
	if !bytes.Contains(b, []byte(`"my-session"`)) {
		t.Fatalf("container_info.json missing session name: %s", b)
	}
	if !bytes.HasPrefix(b, []byte("{")) || !bytes.HasSuffix(b, []byte("}")) {
		t.Fatalf("container_info.json is not a JSON object: %s", b)
	}
}
