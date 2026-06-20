// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// faultyFile is an in-package syncWriteCloser used to drive FileSink's durability
// deny branches that a real os.File on a regular file does not fault on demand: a
// short write, a write error, and an fsync error. Each fault is the exact failure the
// ChainSink's fail-closed branch must treat as a hard deny.
type faultyFile struct {
	short    bool // report a short write (n < len(p)) with no error
	writeErr error
	syncErr  error
}

func (f faultyFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(p) - 1, nil // one byte short, no error: the short-write deny branch
	}
	return len(p), nil
}

func (f faultyFile) Sync() error  { return f.syncErr }
func (f faultyFile) Close() error { return nil }

// TestFileSinkWriteShortWriteDenies proves a short append (fewer bytes written than
// the line holds, with no error) is a durability failure: Write returns non-nil so a
// torn line never enters the spine and the action is denied.
func TestFileSinkWriteShortWriteDenies(t *testing.T) {
	t.Parallel()
	sink := &FileSink{f: faultyFile{short: true}}
	if err := sink.Write(context.Background(), ChainEnvelope{Source: "control", Sequence: 1}); err == nil {
		t.Fatal("Write on a short append = nil, want a durability error (fail-closed deny)")
	}
}

// TestFileSinkWriteAppendErrorDenies proves an append error is surfaced as a deny.
func TestFileSinkWriteAppendErrorDenies(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("disk full")
	sink := &FileSink{f: faultyFile{writeErr: sentinel}}
	err := sink.Write(context.Background(), ChainEnvelope{Source: "control", Sequence: 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write on an append error = %v, want it to wrap %v", err, sentinel)
	}
}

// TestFileSinkWriteFsyncErrorDenies proves an fsync failure AFTER a successful append
// is still a deny: durability before ack means a flush that does not reach stable
// storage denies the privileged action.
func TestFileSinkWriteFsyncErrorDenies(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("fsync failed")
	sink := &FileSink{f: faultyFile{syncErr: sentinel}}
	err := sink.Write(context.Background(), ChainEnvelope{Source: "control", Sequence: 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write on an fsync error = %v, want it to wrap %v", err, sentinel)
	}
}

// TestFileSinkWriteFailsWhenUnderlyingFileClosed forces the real append/fsync error
// branch: the underlying *os.File is closed out from under the sink while the sink's
// own closed flag stays false, so Write reaches s.f.Write (and would reach s.f.Sync)
// on a closed descriptor and must return a non-nil error. This is the durability-
// failure path the ChainSink's fail-closed deny depends on; an in-package test is the
// only way to drive it deterministically (the public API closes the flag and the file
// together). Without this branch a write fault would be invisible.
func TestFileSinkWriteFailsWhenUnderlyingFileClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	// Close the descriptor directly, NOT through sink.Close, so sink.closed stays false
	// and Write proceeds into the real os.File write path on a closed fd.
	if err := sink.f.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}
	if err := sink.Write(context.Background(), ChainEnvelope{Source: "control", Sequence: 1}); err == nil {
		t.Fatal("Write to a closed underlying descriptor = nil, want a durability error (fail-closed deny)")
	}
}

// TestFileSinkCloseSurfacesUnderlyingError forces the Close error branch: the
// underlying descriptor is already closed, so the sink's Close (with closed still
// false) calls s.f.Close on a closed fd and surfaces the resulting error rather than
// swallowing it. An in-package test is the only way to reach this without the public
// idempotent-Close short-circuit.
func TestFileSinkCloseSurfacesUnderlyingError(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	if err := sink.f.Close(); err != nil {
		t.Fatalf("close underlying file: %v", err)
	}
	if err := sink.Close(); err == nil {
		t.Fatal("Close over an already-closed descriptor = nil, want the surfaced close error")
	}
}
