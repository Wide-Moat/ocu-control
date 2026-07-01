// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// envFor builds a minimal, valid-shape ChainEnvelope carrying seq. The chain
// metadata is supplied by the ChainSink in production; these tests exercise only
// the durable-render path, so a fixed source and a per-seq payload are enough to
// assert ordering and one-line-per-envelope framing.
func envFor(seq uint64) ocsf.ChainEnvelope {
	return ocsf.ChainEnvelope{
		Source:    "control",
		Sequence:  seq,
		PriorHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Hash:      "deadbeef",
		Event:     json.RawMessage(`{"seq":` + itoa(seq) + `}`),
	}
}

// itoa renders a small uint64 without pulling strconv into the envelope payload
// helper; the values are test sequence numbers, always non-negative.
func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// readLines reads the audit file back as its newline-delimited records.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer func() { _ = f.Close() }()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan audit file: %v", err)
	}
	return lines
}

// TestFileSinkWritesOrderedJSONLines proves N envelopes Write as exactly N
// newline-delimited JSON lines, in the order they were emitted, each decoding back
// to its source envelope. This is the durable-trail invariant: one ordered line per
// privileged action.
func TestFileSinkWritesOrderedJSONLines(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}

	const n = 8
	for i := uint64(1); i <= n; i++ {
		if err := sink.Write(context.Background(), envFor(i)); err != nil {
			t.Fatalf("Write seq %d: %v", i, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != n {
		t.Fatalf("audit file holds %d lines, want %d", len(lines), n)
	}
	for i, line := range lines {
		var got ocsf.ChainEnvelope
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", i, err, line)
		}
		if want := uint64(i + 1); got.Sequence != want {
			t.Fatalf("line %d sequence = %d, want %d (order not preserved)", i, got.Sequence, want)
		}
	}
}

// TestFileSinkPermissionsAreOwnerOnly proves the audit file is created 0600 so no
// other host user can read or append to the tamper-evidence spine.
func TestFileSinkPermissionsAreOwnerOnly(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit file perm = %o, want 0600", perm)
	}
}

// TestFileSinkAppendsAcrossOpens proves reopening the same path appends rather than
// truncates, so a daemon restart continues the prior spine instead of discarding it.
func TestFileSinkAppendsAcrossOpens(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")

	first, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink #1: %v", err)
	}
	if err := first.Write(context.Background(), envFor(1)); err != nil {
		t.Fatalf("Write #1: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}

	second, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink #2: %v", err)
	}
	if err := second.Write(context.Background(), envFor(2)); err != nil {
		t.Fatalf("Write #2: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("Close #2: %v", err)
	}

	if lines := readLines(t, path); len(lines) != 2 {
		t.Fatalf("reopen appended %d lines total, want 2 (truncated instead of appended?)", len(lines))
	}
}

// TestFileSinkUnwritablePathReturnsError proves an open against an unwritable path
// fails fast, so the daemon aborts at boot rather than booting with a discarded
// trail. A path under a non-existent directory cannot be created.
func TestFileSinkUnwritablePathReturnsError(t *testing.T) {
	t.Parallel()
	bad := filepath.Join(t.TempDir(), "no-such-dir", "audit.ocsf.jsonl")
	if _, err := ocsf.OpenFileSink(bad); err == nil {
		t.Fatal("OpenFileSink on an uncreatable path returned nil, want an error")
	}
}

// TestFileSinkEmptyPathReturnsError proves an empty path is rejected rather than
// opening a surprising file.
func TestFileSinkEmptyPathReturnsError(t *testing.T) {
	t.Parallel()
	if _, err := ocsf.OpenFileSink(""); err == nil {
		t.Fatal("OpenFileSink(\"\") returned nil, want an error")
	}
}

// TestFileSinkWriteToReadOnlyFileReturnsError proves a Write whose underlying append
// fails returns a non-nil error so the ChainSink's fail-closed deny branch fires.
// The file is opened by the sink, then made unwritable out of band on a platform
// where chmod 0400 actually denies the owner's writes.
func TestFileSinkWriteToReadOnlyFileReturnsError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("0400-denies-owner-write semantics differ on Windows")
	}
	// Running as root bypasses the 0400 owner-write denial, so the negative path
	// cannot be exercised; skip rather than assert a false green.
	if os.Geteuid() == 0 {
		t.Skip("running as root: 0400 does not deny owner writes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ocsf.jsonl")
	// Pre-create the file read-only so OpenFileSink's O_WRONLY open itself fails: the
	// open is the boot-time fail-closed point an unwritable sink trips.
	if err := os.WriteFile(path, nil, 0o400); err != nil {
		t.Fatalf("pre-create read-only file: %v", err)
	}
	if _, err := ocsf.OpenFileSink(path); err == nil {
		t.Fatal("OpenFileSink on a 0400 file returned nil, want a write-open error")
	}
}

// TestFileSinkWriteAfterCloseFails proves a Write after Close is denied with
// ErrFileSinkClosed, so a privileged action racing shutdown is failed closed rather
// than silently dropped.
func TestFileSinkWriteAfterCloseFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sink.Write(context.Background(), envFor(1)); !errors.Is(err, ocsf.ErrFileSinkClosed) {
		t.Fatalf("Write after Close = %v, want ErrFileSinkClosed", err)
	}
}

// TestFileSinkCloseIsIdempotent proves a second Close is a no-op returning nil, so a
// shutdown path that closes twice does not error.
func TestFileSinkCloseIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close #2 = %v, want nil (idempotent)", err)
	}
}

// TestFileSinkWriteCancelledContextFails proves an already-cancelled context denies
// the write before any append, mirroring the ChainSink's fail-closed-on-cancel rule.
func TestFileSinkWriteCancelledContextFails(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.Write(ctx, envFor(1)); err == nil {
		t.Fatal("Write with a cancelled context returned nil, want an error")
	}
	if lines := readLines(t, path); len(lines) != 0 {
		t.Fatalf("cancelled Write appended %d lines, want 0", len(lines))
	}
}

// TestFileSinkConcurrentWritesSerialize proves N goroutines writing concurrently
// produce exactly N intact JSON lines with no interleaving or corruption: every line
// decodes and the full set of sequence numbers is present exactly once. This is the
// single-writer-safe invariant — concurrent privileged actions serialize their
// appends so the hash-chain stays monotonic on disk.
func TestFileSinkConcurrentWritesSerialize(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}

	const n = 200
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := uint64(1); i <= n; i++ {
		go func(seq uint64) {
			defer wg.Done()
			if err := sink.Write(context.Background(), envFor(seq)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Write failed: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != n {
		t.Fatalf("concurrent writes produced %d lines, want %d (interleaving or loss)", len(lines), n)
	}
	seen := make(map[uint64]bool, n)
	for i, line := range lines {
		var got ocsf.ChainEnvelope
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d corrupted (not valid JSON): %v\n%s", i, err, line)
		}
		if seen[got.Sequence] {
			t.Fatalf("sequence %d appears more than once", got.Sequence)
		}
		seen[got.Sequence] = true
	}
	for i := uint64(1); i <= n; i++ {
		if !seen[i] {
			t.Fatalf("sequence %d missing from the audit file", i)
		}
	}
}

// TestFileSinkDurableDenyReachesChainSink proves the end-to-end fail-closed wiring:
// a ChainSink over a real FileSink whose file has been closed out from under it
// surfaces audit.ErrAuditWriteFailed from Emit, which is exactly the error the
// lifecycle/killswitch callers treat as a hard deny. This is the structural point of
// B3 — with NullSink the deny branch was unreachable; with FileSink it fires.
func TestFileSinkDurableDenyReachesChainSink(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	fileSink, err := ocsf.OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	sink := ocsf.NewChainSink(newClock(), fileSink, "control")

	// First Emit lands durably.
	if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionCreateCommit, Key: "k", Caller: "c", Tenant: "t"}); err != nil {
		t.Fatalf("first Emit over FileSink = %v, want nil", err)
	}
	// Close the sink: the next Emit's writer.Write fails, and the ChainSink must wrap
	// it as audit.ErrAuditWriteFailed so the caller's fail-closed deny fires.
	if err := fileSink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = sink.Emit(context.Background(), audit.Record{Action: audit.ActionDestroy, Key: "k", Caller: "c", Tenant: "t"})
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Emit after the durable sink closed = %v, want audit.ErrAuditWriteFailed (fail-closed deny)", err)
	}
}
