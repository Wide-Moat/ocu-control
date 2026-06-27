// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
)

// validKey returns a 32-byte all-ones key the length check accepts, so a Stage
// reaches the filesystem writes the failure-injection tests target.
func validKey() []byte {
	k := make([]byte, ed25519.PublicKeySize)
	for i := range k {
		k[i] = 1
	}
	return k
}

// TestWriteFileExactParentUnwritable proves writeFileExact returns an error (and
// stages nothing) when the parent directory cannot hold the temp file: a 0500
// (read+execute, no write) directory makes os.CreateTemp fail, exercising the
// create-temp error branch. The test skips as root (where mode bits are bypassed).
func TestWriteFileExactParentUnwritable(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory write permission; mode-based denial is not observable")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("mkdir read-only dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) }) // let t.TempDir cleanup succeed

	err := writeFileExact(filepath.Join(roDir, "artifact.bin"), []byte("payload"), roFilePerm)
	if err == nil {
		t.Fatal("writeFileExact into an unwritable directory returned nil; want a create-temp error")
	}
}

// TestStageFailClosedRemovesPartialRoot proves the fs-rollback branch: when a
// filesystem write fails AFTER the per-session root exists, failClosed removes the
// partial root and returns ErrStageFailed, so nothing half-written survives. We
// drive it by making the per-session root read-only after MkdirAll so the sock-dir
// MkdirAll inside it fails. The test skips as root.
func TestStageFailClosedRemovesPartialRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory write permission; mode-based denial is not observable")
	}
	base := t.TempDir()
	s := &fsStager{base: base}

	// Pre-create the per-session root read-only so the sock-dir MkdirAll under it
	// fails, taking the post-root failClosed branch. Stage re-chmods the root to 0700
	// first, so we must defeat that: make the BASE read-only after the root exists is
	// not enough (root already exists). Instead, pre-create the root as a 0500 dir;
	// Stage's MkdirAll(root) is a no-op on an existing dir, its Chmod(root,0700)
	// succeeds (we own it), but then we cannot block the sock dir. So drive the
	// failure at the sock-dir level by planting a FILE where the sock dir must go.
	const name ocuruntime.SessionName = "sess-failclosed"
	root := filepath.Join(base, string(name))
	if err := os.MkdirAll(root, dirPerm); err != nil {
		t.Fatalf("seed root: %v", err)
	}
	// A regular file at the sock-dir path makes os.MkdirAll(sockDir) fail with
	// "not a directory", driving the failClosed rollback.
	if err := os.WriteFile(filepath.Join(root, sockDirName), []byte("x"), 0o600); err != nil {
		t.Fatalf("plant file at sock-dir path: %v", err)
	}

	_, err := s.Stage(context.Background(), name, validKey(), nil)
	if !errors.Is(err, ErrStageFailed) {
		t.Fatalf("Stage with a blocked sock dir = %v; want ErrStageFailed", err)
	}
	// failClosed removed the partial root: nothing half-written survives.
	if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial root still present after failClosed: stat err = %v; want not-exist", statErr)
	}
}

// TestStageWriteArtifactRenameFails drives writeFileExact's rename-into-place
// failure (and thus Stage's "write container_info.json" failClosed branch) by
// planting a DIRECTORY where the container_info.json file must land: os.Rename of
// the temp file onto an existing non-empty directory fails, so writeFileExact
// returns the rename error and Stage rolls the partial root back.
func TestStageWriteArtifactRenameFails(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	s := &fsStager{base: base}

	const name ocuruntime.SessionName = "sess-rename-fail"
	root := filepath.Join(base, string(name))
	if err := os.MkdirAll(filepath.Join(root, sockDirName), dirPerm); err != nil {
		t.Fatalf("seed root+sockdir: %v", err)
	}
	// A non-empty directory at the container_info.json path: os.Rename(tmp, dir)
	// cannot replace a non-empty directory, so the write fails closed.
	infoDir := filepath.Join(root, containerInfoFile)
	if err := os.MkdirAll(filepath.Join(infoDir, "blocker"), dirPerm); err != nil {
		t.Fatalf("plant directory at container_info path: %v", err)
	}

	_, err := s.Stage(context.Background(), name, validKey(), nil)
	if !errors.Is(err, ErrStageFailed) {
		t.Fatalf("Stage with a blocked container_info path = %v; want ErrStageFailed", err)
	}
	if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial root still present after a write failure: stat err = %v", statErr)
	}
}

// TestWriteFileExactRenameOntoDirFails isolates the rename-into-place failure of
// writeFileExact: a non-empty directory at the destination path defeats the atomic
// rename, so the function returns the wrapped rename error.
func TestWriteFileExactRenameOntoDirFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, "artifact.bin")
	if err := os.MkdirAll(filepath.Join(dest, "child"), 0o700); err != nil {
		t.Fatalf("plant non-empty directory at dest: %v", err)
	}
	if err := writeFileExact(dest, []byte("payload"), roFilePerm); err == nil {
		t.Fatal("writeFileExact onto a non-empty directory returned nil; want a rename error")
	}
}

// TestStageMkdirRootFails drives the MkdirAll(root) failure branch (before any
// failClosed is owed): when the stager base is a regular FILE rather than a
// directory, creating the per-session root under it fails and Stage returns
// ErrStageFailed having written nothing.
func TestStageMkdirRootFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	baseFile := filepath.Join(dir, "base-is-a-file")
	if err := os.WriteFile(baseFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed base file: %v", err)
	}
	s := &fsStager{base: baseFile}

	_, err := s.Stage(context.Background(), "sess-mkdir-fail", validKey(), nil)
	if !errors.Is(err, ErrStageFailed) {
		t.Fatalf("Stage with a file as base = %v; want ErrStageFailed", err)
	}
}

// TestStagePublicKeyWriteFails drives the write-public-key failClosed branch: the
// container_info.json write succeeds, then a planted DIRECTORY at the public-key
// path defeats the public-key rename, so Stage fails closed and rolls the root back.
func TestStagePublicKeyWriteFails(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	s := &fsStager{base: base}

	const name ocuruntime.SessionName = "sess-pubkey-fail"
	root := filepath.Join(base, string(name))
	if err := os.MkdirAll(filepath.Join(root, sockDirName), dirPerm); err != nil {
		t.Fatalf("seed root+sockdir: %v", err)
	}
	// A non-empty directory at the public-key path: the container_info write lands
	// first, then this defeats the public-key rename.
	keyDir := filepath.Join(root, publicKeyFile)
	if err := os.MkdirAll(filepath.Join(keyDir, "blocker"), dirPerm); err != nil {
		t.Fatalf("plant directory at public-key path: %v", err)
	}

	_, err := s.Stage(context.Background(), name, validKey(), nil)
	if !errors.Is(err, ErrStageFailed) {
		t.Fatalf("Stage with a blocked public-key path = %v; want ErrStageFailed", err)
	}
	if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial root still present after a public-key write failure: stat err = %v", statErr)
	}
}

// TestFailClosedDirectly exercises the failClosed helper in isolation: it removes
// the supplied root and returns a wrapped ErrStageFailed carrying the step label.
func TestFailClosedDirectly(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	s := &fsStager{base: base}
	root := filepath.Join(base, "to-remove")
	if err := os.MkdirAll(root, dirPerm); err != nil {
		t.Fatalf("seed root: %v", err)
	}

	_, err := s.failClosed(root, "write public key", errors.New("disk full"))
	if !errors.Is(err, ErrStageFailed) {
		t.Fatalf("failClosed = %v; want ErrStageFailed", err)
	}
	if _, statErr := os.Stat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failClosed did not remove the root: stat err = %v", statErr)
	}
}

// fakeTempFile is a tempFile that wraps a real *os.File (so Name/Sync/Close behave
// on a real fd) while letting a test force any one method to fail or short-write.
// It is the fault-injection vehicle for writeFileExact's os.File error branches,
// which a real filesystem cannot reproduce on demand.
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

// withFakeTemp installs a createTemp that returns a fakeTempFile configured by mut,
// and restores the original on cleanup. It is the seam mirroring the docker
// Deps.API fake-injection pattern: production createTemp is untouched; only the
// test swaps it.
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

// TestWriteFileExactInjectedFaults drives every os.File error branch of
// writeFileExact through the createTemp seam: a chmod failure, a write failure, a
// short write, a sync failure, and a close failure each return an error so a
// truncated or unsynced artifact never reaches a container. The short-write case
// is the load-bearing one the package doc names.
func TestWriteFileExactInjectedFaults(t *testing.T) {
	injected := errors.New("injected fault")
	cases := []struct {
		name string
		mut  func(f *fakeTempFile)
	}{
		{"chmod", func(f *fakeTempFile) { f.chmodErr = injected }},
		{"write", func(f *fakeTempFile) { f.writeErr = injected }},
		{"short-write", func(f *fakeTempFile) { f.shortWrite = true }},
		{"sync", func(f *fakeTempFile) { f.syncErr = injected }},
		{"close", func(f *fakeTempFile) { f.closeErr = injected }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withFakeTemp(t, c.mut)
			dir := t.TempDir()
			err := writeFileExact(filepath.Join(dir, "artifact.bin"), []byte("payload"), roFilePerm)
			if err == nil {
				t.Fatalf("writeFileExact with injected %s fault returned nil; want an error", c.name)
			}
		})
	}
}

// TestStageChmodFails drives Stage's two chmod failClosed branches (the 0700
// re-assertion on the root and the sock dir) through the chmod seam. The first
// chmod call is the root; failing it returns ErrStageFailed and rolls the partial
// root back. The second chmod call is the sock dir; failing only that one (the root
// chmod having succeeded) exercises the sock-dir branch. A chmod failure on an
// owned directory is not portably reproducible, so the seam is the only way to
// reach these defensive branches.
func TestStageChmodFails(t *testing.T) {
	injected := errors.New("injected chmod fault")

	t.Run("root", func(t *testing.T) {
		orig := chmod
		t.Cleanup(func() { chmod = orig })
		chmod = func(string, os.FileMode) error { return injected }

		base := t.TempDir()
		s := &fsStager{base: base}
		_, err := s.Stage(context.Background(), "sess-chmod-root", validKey(), nil)
		if !errors.Is(err, ErrStageFailed) {
			t.Fatalf("Stage with a failing root chmod = %v; want ErrStageFailed", err)
		}
	})

	t.Run("sockdir", func(t *testing.T) {
		orig := chmod
		t.Cleanup(func() { chmod = orig })
		calls := 0
		chmod = func(path string, m os.FileMode) error {
			calls++
			if calls == 1 {
				return orig(path, m) // let the root chmod succeed
			}
			return injected // fail the sock-dir chmod
		}

		base := t.TempDir()
		s := &fsStager{base: base}
		_, err := s.Stage(context.Background(), "sess-chmod-sock", validKey(), nil)
		if !errors.Is(err, ErrStageFailed) {
			t.Fatalf("Stage with a failing sock-dir chmod = %v; want ErrStageFailed", err)
		}
	})
}

// TestUnstageRemoveError proves Unstage surfaces a remove failure rather than
// silently succeeding. We point Root at a child of a read-only parent so RemoveAll
// cannot unlink it. The test skips as root and on platforms where the unlink is not
// permission-gated this way.
func TestUnstageRemoveError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory write permission; remove denial is not observable")
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory-permission semantics not applicable")
	}
	base := t.TempDir()
	s := &fsStager{base: base}

	parent := filepath.Join(base, "locked")
	child := filepath.Join(parent, "root")
	if err := os.MkdirAll(child, dirPerm); err != nil {
		t.Fatalf("seed child: %v", err)
	}
	// Make the parent read-only so the child cannot be unlinked from it.
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod parent read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	err := s.Unstage(context.Background(), Staged{Root: child})
	if err == nil {
		t.Fatal("Unstage of an unremovable root returned nil; want a remove error")
	}
}

// TestUnstageCancelledContext proves Unstage refuses on a cancelled context before
// touching the filesystem.
func TestUnstageCancelledContext(t *testing.T) {
	t.Parallel()
	s := &fsStager{base: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Unstage(ctx, Staged{Root: "/anything"}); err == nil {
		t.Fatal("Unstage on a cancelled context returned nil; want an error")
	}
}
