// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// onePub returns a single renderable Ed25519 public key so writeAtomic's fault
// branches are exercised over a real, non-empty Set.
func onePub(t *testing.T) []cred.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return []cred.PublicKey{{KID: "k-internal", Alg: cred.AlgEdDSA, Pub: pub}}
}

// fakeTempFile wraps a real *os.File (so Name/Sync/Close behave on a real fd)
// while letting a test force any one method to fail or short-write. It is the
// fault-injection vehicle for writeAtomic's os.File error branches, which a real
// filesystem cannot reproduce on demand. It mirrors the same seam in
// internal/handoff.
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
		return n - 1, err // report a short write while leaving the data intact
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

// withFakeTemp installs a createTemp that returns a fakeTempFile configured by
// mut, and restores the original on cleanup. Production createTemp is untouched;
// only the test swaps it.
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

// TestWriteAtomicInjectedFaults drives every os.File error branch of writeAtomic
// through the createTemp seam: a chmod failure, a write failure, a short write, a
// sync failure, and a close failure each return an error and write NO destination
// file, so a truncated or unsynced JWKS never lands at the served path. The
// short-write case proves the length guard fires even when the underlying write
// reports no error.
func TestWriteAtomicInjectedFaults(t *testing.T) {
	boom := errors.New("injected fault")
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
			path := filepath.Join(dir, "jwks.json")
			err := WriteArtifact(path, onePub(t))
			if err == nil {
				t.Fatalf("WriteArtifact under an injected %s fault returned nil; want an error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("WriteArtifact %s error %q does not mention %q", tc.name, err, tc.wantSub)
			}
			// No destination file: a faulted write never lands a partial Set at path.
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s fault left a destination file (stat err=%v); want none", tc.name, statErr)
			}
			// No leftover temp file: the deferred cleanup ran on the fault path.
			entries, rdErr := os.ReadDir(dir)
			if rdErr != nil {
				t.Fatalf("readdir: %v", rdErr)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".tmp-jwks-") {
					t.Fatalf("%s fault left a temp file %q; want cleaned up", tc.name, e.Name())
				}
			}
		})
	}
}

// TestWriteAtomicCreateTempFails proves the create-temp error branch: when the
// temp file cannot be created (here the parent directory does not exist), the
// error is surfaced and no destination file lands.
func TestWriteAtomicCreateTempFails(t *testing.T) {
	t.Parallel()
	// A path whose parent directory does not exist makes os.CreateTemp(dir, ...)
	// fail at the create step, before any temp file exists.
	path := filepath.Join(t.TempDir(), "no-such-subdir", "jwks.json")
	err := WriteArtifact(path, onePub(t))
	if err == nil {
		t.Fatal("WriteArtifact into a missing directory returned nil; want a create-temp error")
	}
	if !strings.Contains(err.Error(), "create temp") {
		t.Fatalf("error %q does not mention the create-temp step", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("create-temp fault left a destination file (stat err=%v); want none", statErr)
	}
}
