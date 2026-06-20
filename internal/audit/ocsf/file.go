// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// fileSinkPerm is the 0600 mode the audit file is created with: owner read/write
// only. The audit spine carries no credential, but it is a tamper-evidence record
// of every privileged action, so no other host user may read or append to it.
const fileSinkPerm = 0o600

// ErrFileSinkClosed is returned by a Write or Close after the FileSink has been
// closed. It is the fail-closed verdict for a write that races shutdown: a
// privileged action whose audit envelope arrives after the sink is closed is
// denied rather than silently dropped.
var ErrFileSinkClosed = errors.New("ocsf: audit file sink is closed")

// FileSink is the durable, single-writer EventWriter that backs -audit-sink with a
// real append-only file. Each ChainEnvelope is serialized as exactly one JSON line
// (newline-delimited JSON), appended, and fsync'd BEFORE Write returns — so the
// privileged action that triggered the emit is not acknowledged until its event is
// on durable storage. A write or fsync failure returns a non-nil error, which the
// ChainSink wraps as audit.ErrAuditWriteFailed and the caller's fail-closed branch
// treats as a hard deny: this writer is precisely what makes "every privileged
// action is durably audited before ack, or it is denied" reachable.
//
// It is single-writer safe: a mutex serializes concurrent appends so two privileged
// actions never interleave their bytes, and the file's hash-chain stays in the
// monotonic order the ChainSink assigned under its own lock. The sink does NOT
// compute or alter the chain — the ChainEnvelope arrives already sequenced and
// linked; FileSink only renders and flushes it.
type FileSink struct {
	mu     sync.Mutex
	f      syncWriteCloser
	closed bool
}

// syncWriteCloser is the narrow durable-file contract FileSink drives: append bytes,
// flush them to stable storage, and close. *os.File satisfies it in production; an
// in-package test substitutes a faulting implementation to drive the short-write and
// fsync-failure deny branches deterministically, since a real os.File on a regular
// file does not fault those paths on demand.
type syncWriteCloser interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// Compile-time proof FileSink satisfies the EventWriter seam the ChainSink writes
// to, so it slots in behind NewChainSink with no call-site change, and that *os.File
// satisfies the durable-file contract FileSink drives.
var (
	_ EventWriter     = (*FileSink)(nil)
	_ syncWriteCloser = (*os.File)(nil)
)

// OpenFileSink opens (or creates) path as an append-only audit file with 0600
// permissions and returns a FileSink that durably appends each envelope. The file
// is opened O_APPEND|O_CREATE|O_WRONLY so existing chain lines are preserved and
// every write lands at the end — a restart continues the prior spine rather than
// truncating it. An open failure (e.g. an unwritable directory) is returned so the
// daemon aborts at boot rather than booting with a discarded audit trail.
func OpenFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, errors.New("ocsf: audit file sink path is empty")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileSinkPerm)
	if err != nil {
		return nil, fmt.Errorf("ocsf: open audit sink %q: %w", path, err)
	}
	return &FileSink{f: f}, nil
}

// Write serializes env as one JSON line, appends it, and fsyncs the file before
// returning. It returns a non-nil error on any marshal, write, or fsync failure (or
// after Close), so the ChainSink's fail-closed branch denies the privileged action
// rather than acknowledging an event that did not reach durable storage. A short
// write is treated as a failure. The mutex makes the append + fsync atomic with
// respect to other concurrent Writes, so the file's lines stay in the monotonic
// order the ChainSink assigned and no two envelopes interleave their bytes.
func (s *FileSink) Write(ctx context.Context, env ChainEnvelope) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ocsf: audit file write: context: %w", err)
	}

	// Marshal BEFORE taking the lock: a serialization fault denies the action and
	// holds the lock for the minimum window. The envelope is a fixed, JSON-safe shape,
	// so a marshal failure is not expected, but the branch is real and fail-closed.
	line, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("ocsf: marshal audit envelope (seq %d): %w", env.Sequence, err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrFileSinkClosed
	}

	// One newline-delimited JSON record per envelope. A short write is a durability
	// failure: the action is denied so a torn line never enters the spine.
	n, err := s.f.Write(line)
	if err != nil {
		return fmt.Errorf("ocsf: append audit envelope (seq %d): %w", env.Sequence, err)
	}
	if n != len(line) {
		return fmt.Errorf("ocsf: short audit append (seq %d): wrote %d of %d bytes", env.Sequence, n, len(line))
	}

	// fsync before returning: durability BEFORE ack is the whole point. Without this
	// flush the bytes could sit in the page cache and be lost on a crash, so the
	// privileged action would be acknowledged on a non-durable event.
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("ocsf: fsync audit envelope (seq %d): %w", env.Sequence, err)
	}
	return nil
}

// Close flushes and closes the underlying file. It is idempotent: a second Close is
// a no-op returning nil. After Close, every Write fails with ErrFileSinkClosed so a
// privileged action racing shutdown is denied rather than silently dropped. Close is
// called once on daemon shutdown after the listeners have drained.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("ocsf: close audit sink: %w", err)
	}
	return nil
}
