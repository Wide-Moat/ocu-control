// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package guestexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/dial"
	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
)

// execSockName is the exec-channel UDS filename inside the session's staged sock
// directory — the same name the Docker provider passes to the guest exec server's
// --listen-uds (runtime/docker keeps its own unexported copy; the two are pinned
// together by the end-to-end dial, not by a shared symbol, so this client package
// never imports the docker provider).
const execSockName = "exec.sock"

// totalExecCap is the MANDATORY total exec bound (D-03): dial + handshake + the
// whole drive. A requested timeout above it is CLAMPED down, never honored.
const totalExecCap = 5 * time.Minute

// defaultStdioCap bounds each captured output stream (05-SS): bytes past the cap
// are discarded with the truncated flag set, so a flooding guest cannot balloon
// host memory through an exec result.
const defaultStdioCap = 8 << 20

// Request is one exec request against a session's guest: the command vector and
// its optional environment, working directory, stdin bytes, and timeout. It
// carries NO credential and NO addressing authority — the session is addressed
// by the caller through the host-derived row, never by a field here.
type Request struct {
	// Argv is the command vector; Argv[0] is the program. It must be non-empty.
	Argv []string
	// Env is the optional child environment (added to the guest's base).
	Env map[string]string
	// Cwd is the optional working directory inside the guest.
	Cwd string
	// Stdin is the optional stdin payload, pumped to the child and closed with
	// EOF. Nil/empty means no stdin (no ExpectStdIn frame is ever emitted).
	Stdin []byte
	// TimeoutS bounds the exec in whole seconds. Zero means the total cap; any
	// value above the cap is clamped to it (D-03).
	TimeoutS uint32
}

// Result is the completed exec: the guest child's exit code and the captured,
// per-stream-bounded output.
type Result struct {
	ExitCode        uint8
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
}

// Driver is the control-plane exec driver (ADR-0024): it serializes execs per
// session (NFR-IC-05), gates the staged sock directory, mints the per-dial
// container-bound Session JWT, and drives one process over the frozen
// exec-channel wire.
type Driver struct {
	mint execMinter
	// stdioCap bounds each captured stream; a test tightens it, production keeps
	// the default.
	stdioCap int64

	// mu guards sessions; each session's own mutex serializes its execs.
	mu       sync.Mutex
	sessions map[string]*sync.Mutex
}

// NewDriver builds a Driver over the narrow mint seam.
func NewDriver(mint execMinter) *Driver {
	return &Driver{
		mint:     mint,
		stdioCap: defaultStdioCap,
		sessions: make(map[string]*sync.Mutex),
	}
}

// sessionLock returns the one mutex serializing execs for sockDir, creating it
// on first use. Entries are never removed: a session's staged dir is unique per
// session key and the map grows only with live-session cardinality.
func (d *Driver) sessionLock(sockDir string) *sync.Mutex {
	d.mu.Lock()
	defer d.mu.Unlock()
	l, ok := d.sessions[sockDir]
	if !ok {
		l = &sync.Mutex{}
		d.sessions[sockDir] = l
	}
	return l
}

// effectiveTimeout maps the wire timeout to the bounded exec deadline: zero
// means the total cap, anything above the cap clamps to it (D-03).
func effectiveTimeout(timeoutS uint32) time.Duration {
	if timeoutS == 0 {
		return totalExecCap
	}
	dur := time.Duration(timeoutS) * time.Second
	if dur > totalExecCap {
		return totalExecCap
	}
	return dur
}

// cappedWriter captures up to limit bytes and discards the rest, recording that
// truncation happened. It never errors: a flooded stream must not abort the
// drive (the exit code is still the truth of the exec), it only stops growing.
type cappedWriter struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	room := w.limit - int64(w.buf.Len())
	if room <= 0 {
		if len(p) > 0 {
			w.truncated = true
		}
		return len(p), nil
	}
	if int64(len(p)) > room {
		w.buf.Write(p[:room])
		w.truncated = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// Exec runs one command in the session's guest: gate the staged sock dir, take
// the session's serialization lock, dial the exec socket with a container-bound
// Session JWT, complete the verbatim handshake carrying the CreateProcess, and
// drive the process to its exit code with bounded output capture.
func (d *Driver) Exec(ctx context.Context, sockDir, containerName string, req Request) (Result, error) {
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return Result{}, errors.New("guestexec: empty argv")
	}
	minter, err := NewMinter(d.mint, containerName)
	if err != nil {
		return Result{}, err
	}
	if err := verifyHostOwnedDir(sockDir); err != nil {
		return Result{}, err
	}

	// One exec at a time per session (NFR-IC-05). The lock is taken BEFORE the
	// timeout starts so a queued exec gets its full window once it runs.
	lock := d.sessionLock(sockDir)
	lock.Lock()
	defer lock.Unlock()

	timeout := effectiveTimeout(req.TimeoutS)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch, err := dial.DialUDS(ctx, filepath.Join(sockDir, execSockName), minter)
	if err != nil {
		return Result{}, fmt.Errorf("guestexec: dial exec channel: %w", err)
	}
	defer func() { _ = ch.Close() }()

	conn, err := buildProcessConnection(req, containerName, timeout)
	if err != nil {
		return Result{}, err
	}
	if err := ch.Handshake(ctx, conn); err != nil {
		return Result{}, fmt.Errorf("guestexec: handshake: %w", err)
	}

	stdout := &cappedWriter{limit: d.stdioCap}
	stderr := &cappedWriter{limit: d.stdioCap}
	// An empty stdin passes a TRUE nil reader so no ExpectStdIn/StdInEOF frame is
	// ever emitted (a typed-nil inside the interface would re-enable the pump).
	var stdin io.Reader
	if len(req.Stdin) > 0 {
		stdin = bytes.NewReader(req.Stdin)
	}
	code, err := ch.DriveExec(ctx, stdin, stdout, stderr)
	if err != nil {
		return Result{}, fmt.Errorf("guestexec: drive exec: %w", err)
	}
	return Result{
		ExitCode:        code,
		Stdout:          stdout.buf.Bytes(),
		Stderr:          stderr.buf.Bytes(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
	}, nil
}

// buildProcessConnection maps the Request onto the frozen handshake envelope: a
// fresh random process id, the CreateProcess body, and the expected container
// name binding the dial to this guest. The guest-side child timeout mirrors the
// host-side bounded ctx so both ends enforce the same window.
func buildProcessConnection(req Request, containerName string, timeout time.Duration) (wire.ProcessConnection, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return wire.ProcessConnection{}, fmt.Errorf("guestexec: process id: %w", err)
	}
	create := &wire.CreateProcess{
		Cmd:  req.Argv[0],
		Args: append([]string(nil), req.Argv[1:]...),
		Env:  req.Env,
	}
	if req.Cwd != "" {
		cwd := req.Cwd
		create.Cwd = &cwd
	}
	// timeout is already clamped to totalExecCap (300s), so the narrowing is
	// bounded; the guard keeps the conversion provably in range regardless.
	if s := timeout / time.Second; s > 0 && s <= totalExecCap/time.Second {
		secs := uint32(s)
		create.Timeout = &secs
	}
	name := containerName
	return wire.ProcessConnection{
		ProcessId:             hex.EncodeToString(idBytes),
		CreateReq:             create,
		ExpectedContainerName: &name,
	}, nil
}
