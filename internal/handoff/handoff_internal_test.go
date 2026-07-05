// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileExactFullContentAndPerm proves writeFileExact lands the exact
// payload at the mode it is GIVEN (not a hardcoded mode) and leaves no temp file
// behind. The short-write branch it guards is defensive against a partial
// os.File.Write; here we pin the success invariant — every byte present, the
// requested mode applied via the explicit Chmod (umask-independent), atomic rename
// done. Both perms are exercised so the test reds if writeFileExact ever ignores
// its perm argument and reverts to a constant.
func TestWriteFileExactFullContentAndPerm(t *testing.T) {
	t.Parallel()
	for _, perm := range []os.FileMode{roFilePerm, filePerm} {
		dir := t.TempDir()
		path := filepath.Join(dir, "artifact.bin")
		payload := bytes.Repeat([]byte{0xAB}, 4096)

		if err := writeFileExact(path, payload, perm); err != nil {
			t.Fatalf("writeFileExact(perm=%o): %v", perm, err)
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
		if gotPerm := info.Mode().Perm(); gotPerm != perm {
			t.Fatalf("perm = %o, want %o (writeFileExact must honor its perm argument)", gotPerm, perm)
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

// TestContainerInfoCarriesContainerName is the exec-identity keystone: the staged
// container_info.json MUST carry a container_name field equal to the deterministic
// container name "ocu-sess-<session>" — the SAME value the Materialize path binds
// as RuntimeID and the exec-signer mints as the JWT sub. The guest binds its own
// identity from this field at boot and rejects any exec-JWT whose sub differs
// (auth/claims.rs). Emitting only session_name (the bare key) left the guest with
// no bound container name, so every exec handshake failed "sub does not match
// container name". Neuter containerInfoFor back to session_name-only, or change the
// prefix, and this reds.
func TestContainerInfoCarriesContainerName(t *testing.T) {
	t.Parallel()
	var info struct {
		SessionName   string `json:"session_name"`
		ContainerName string `json:"container_name"`
	}
	if err := json.Unmarshal(containerInfoFor("sess-x"), &info); err != nil {
		t.Fatalf("container_info.json does not parse: %v", err)
	}
	if want := "ocu-sess-sess-x"; info.ContainerName != want {
		t.Fatalf("container_info container_name = %q; want the deterministic name %q "+
			"(must equal Materialize RuntimeID and the exec-JWT sub)", info.ContainerName, want)
	}
}
