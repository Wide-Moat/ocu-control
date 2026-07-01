// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package provisioning

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
)

// faultTempFile is a tempFile that lands a short write on Write, so the push's
// short-write fail-closed guard is exercised without a real partial-write fault on
// disk. It wraps a real temp file for Name/Chmod/Sync/Close so the rename target
// and cleanup behave realistically.
type faultTempFile struct {
	real *os.File
}

func (f faultTempFile) Name() string              { return f.real.Name() }
func (f faultTempFile) Chmod(m os.FileMode) error { return f.real.Chmod(m) }
func (f faultTempFile) Sync() error               { return f.real.Sync() }
func (f faultTempFile) Close() error              { return f.real.Close() }

// Write reports one byte written regardless of the payload, so writeFileExact's
// n != len(data) short-write guard trips for any non-trivial config.
func (f faultTempFile) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Actually write one byte so the temp file is non-empty, then report the short
	// count so the guard sees a truncated payload.
	_, _ = f.real.Write(p[:1])
	return 1, nil
}

// TestPushShortWriteFailsClosed asserts a short write to the temp file is a hard
// failure (ErrPushFailed): a truncated mount-config never lands on the bind, and
// the partial temp file is cleaned up so nothing half-written survives.
func TestPushShortWriteFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "session-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}

	orig := createTemp
	createTemp = func(dir, pattern string) (tempFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return faultTempFile{real: f}, nil
	}
	defer func() { createTemp = orig }()

	p := NewPusher()
	_, err := p.Push(context.Background(), handoff.Staged{Root: root}, []byte(`{"a":1,"b":2}`))
	if !errors.Is(err, ErrPushFailed) {
		t.Fatalf("short write: want ErrPushFailed, got %v", err)
	}

	// Nothing half-written survives: no mount-config.json and no stray temp file.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("short-write push left artifacts behind: %v", names)
	}
}

// TestPushCreateTempErrorFailsClosed covers writeFileExact's create-temp error
// branch: when the temp file cannot be created the push fails closed (ErrPushFailed)
// and nothing lands on the bind.
func TestPushCreateTempErrorFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "session-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}

	orig := createTemp
	createTemp = func(_, _ string) (tempFile, error) { return nil, errInjectedCreateTemp }
	defer func() { createTemp = orig }()

	p := NewPusher()
	_, err := p.Push(context.Background(), handoff.Staged{Root: root}, []byte(`{"a":1}`))
	if !errors.Is(err, ErrPushFailed) {
		t.Fatalf("create-temp error: want ErrPushFailed, got %v", err)
	}
}

// errInjectedCreateTemp is the typed fault the create-temp seam returns so the push
// reaches writeFileExact's create-temp error branch.
var errInjectedCreateTemp = errors.New("provisioning: injected create-temp fault")

// chmodFailTempFile fails Chmod, so writeFileExact's chmod-temp branch is exercised
// (the config must be 0600 before any byte; a chmod failure is fatal).
type chmodFailTempFile struct{ real *os.File }

func (f chmodFailTempFile) Name() string                { return f.real.Name() }
func (f chmodFailTempFile) Chmod(os.FileMode) error     { return errInjectedChmod }
func (f chmodFailTempFile) Write(p []byte) (int, error) { return f.real.Write(p) }
func (f chmodFailTempFile) Sync() error                 { return f.real.Sync() }
func (f chmodFailTempFile) Close() error                { return f.real.Close() }

var errInjectedChmod = errors.New("provisioning: injected chmod fault")

// TestPushChmodErrorFailsClosed covers writeFileExact's chmod-temp error branch: a
// failure to set 0600 on the temp file fails the push closed and leaves nothing on
// the bind.
func TestPushChmodErrorFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "session-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}

	orig := createTemp
	createTemp = func(dir, pattern string) (tempFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return chmodFailTempFile{real: f}, nil
	}
	defer func() { createTemp = orig }()

	p := NewPusher()
	_, err := p.Push(context.Background(), handoff.Staged{Root: root}, []byte(`{"a":1}`))
	if !errors.Is(err, ErrPushFailed) {
		t.Fatalf("chmod error: want ErrPushFailed, got %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("chmod-fail push left artifacts behind: %d entries", len(entries))
	}
}

// syncFailTempFile fails Sync, so writeFileExact's sync-temp branch is exercised
// (the durability barrier before the rename; a sync failure is fatal).
type syncFailTempFile struct{ real *os.File }

func (f syncFailTempFile) Name() string                { return f.real.Name() }
func (f syncFailTempFile) Chmod(m os.FileMode) error   { return f.real.Chmod(m) }
func (f syncFailTempFile) Write(p []byte) (int, error) { return f.real.Write(p) }
func (f syncFailTempFile) Sync() error                 { return errInjectedSync }
func (f syncFailTempFile) Close() error                { return f.real.Close() }

var errInjectedSync = errors.New("provisioning: injected sync fault")

// TestPushSyncErrorFailsClosed covers writeFileExact's sync-temp error branch: a
// failed durability barrier fails the push closed and leaves nothing on the bind.
func TestPushSyncErrorFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "session-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}

	orig := createTemp
	createTemp = func(dir, pattern string) (tempFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return syncFailTempFile{real: f}, nil
	}
	defer func() { createTemp = orig }()

	p := NewPusher()
	_, err := p.Push(context.Background(), handoff.Staged{Root: root}, []byte(`{"a":1}`))
	if !errors.Is(err, ErrPushFailed) {
		t.Fatalf("sync error: want ErrPushFailed, got %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("sync-fail push left artifacts behind: %d entries", len(entries))
	}
}

// TestScrubRemoveErrorIsSurfaced covers Scrub's remove-error branch: an os.Remove
// failure that is NOT a missing-file (here, the target is a non-empty directory) is
// surfaced rather than swallowed, so a genuine reclamation failure is not masked.
func TestScrubRemoveErrorIsSurfaced(t *testing.T) {
	// A directory containing a child cannot be removed by os.Remove, producing a
	// non-NotExist error the scrub must surface.
	dir := filepath.Join(t.TempDir(), "not-a-file")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write child: %v", err)
	}
	p := NewPusher()
	if err := p.Scrub(context.Background(), Pushed{Path: dir}); err == nil {
		t.Fatal("Scrub of a non-empty directory returned nil; want a surfaced remove error")
	}
}

// TestScrubCanceledContextFailsClosed covers Scrub's ctx.Err() guard: a cancelled
// context refuses the scrub rather than silently no-op'ing, so a dropped caller does
// not mask a reclamation that never ran.
func TestScrubCanceledContextFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := NewPusher()
	if err := p.Scrub(ctx, Pushed{Path: filepath.Join(t.TempDir(), "mount-config.json")}); err == nil {
		t.Fatal("Scrub with a cancelled context returned nil; want the context error")
	}
}
