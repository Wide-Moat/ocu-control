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
	"syscall"
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

// dialWaitBudget bounds the cold-start re-dial poll: create returns the instant a
// guest is materialized, but its exec.sock is not dial-able until the FUSE mount
// and boot-child finish — a sub-second window where an immediate exec would hit a
// connect(2) ENOENT/ECONNREFUSED that is provably TRANSIENT (the row is already
// audience-scoped ACTIVE-and-owned above this driver, so a dial refusal here is a
// not-yet-ready guest, not a wrong/absent one). Rather than surface that transient
// as a refusal, the dial re-tries until the socket comes up. The budget is a few
// seconds — long enough to bridge the real cold window with headroom, short enough
// that a genuinely dead guest fails fast instead of pinning the connection for the
// multi-minute exec cap. It is DISTINCT from totalExecCap: that bounds a running
// command, this bounds only the wait for the socket to appear.
const dialWaitBudget = 5 * time.Second

// redialInterval is the poll cadence across the cold window: short enough that the
// exec starts within a poll tick of the socket appearing (the live window is
// sub-second), long enough not to busy-spin connect(2).
const redialInterval = 75 * time.Millisecond

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

	ch, err := dialWithColdWait(ctx, filepath.Join(sockDir, execSockName), minter)
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
		// A command that outlives the host exec deadline is NOT a transport failure:
		// the ingress would map an error here to a 409 (→ gateway 502), losing the
		// whole result AND the output captured before the kill. Shape it as a VALID
		// exec reply instead — exit code 124 (the timeout(1)/bash convention; exit!=0
		// makes it an isError tool result downstream) with the partial stdout/stderr
		// already streamed into the capture buffers before the deadline, plus a
		// timeout notice. Everything else (protocol, dial, read breaches) stays a
		// genuine error → 409. Only ctx.DeadlineExceeded — the host-side exec timeout
		// (effectiveTimeout above) — takes this reply path; a guest-returned natural
		// exit already flows through the success return below.
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == context.DeadlineExceeded {
			notice := fmt.Sprintf("\n[Command timed out after %ds]\n", int(timeout/time.Second))
			// The notice rides the SAME stream that carries the partial output. The
			// downstream relay shows stderr and DROPS stdout on an isError result, so
			// a notice placed only in stderr would hide the partial stdout from the
			// caller — the load-bearing output #129 exists to preserve. Appending to
			// stdout keeps the partial stdout + notice together; also appending to a
			// non-empty stderr means the notice survives whichever stream the relay
			// picks (stderr, when the child wrote to it).
			outBytes := append(stdout.buf.Bytes(), []byte(notice)...)
			errBytes := stderr.buf.Bytes()
			if len(errBytes) > 0 {
				errBytes = append(errBytes, []byte(notice)...)
			}
			return Result{
				ExitCode:        124,
				Stdout:          outBytes,
				Stderr:          errBytes,
				StdoutTruncated: stdout.truncated,
				StderrTruncated: stderr.truncated,
			}, nil
		}
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

// dialWithColdWait dials the exec socket, re-dialling across the sub-second cold
// window where the guest is materialized but has not yet bound exec.sock. A dial
// that fails with a PROVABLY-TRANSIENT connect(2) error (ENOENT: the socket file
// is not there yet; ECONNREFUSED: it is bound but the listener is not accepting
// yet) is retried on redialInterval until the socket comes up or the wait budget
// expires. Any OTHER dial error — a handshake failure, a context cancellation, an
// unexpected syscall — is returned at once: only the not-yet-ready shape is
// transient, everything else is terminal and re-dialling it would only burn the
// budget.
//
// The wait is bounded by min(dialWaitBudget, the caller's ctx deadline): the cold
// wait never outlives the exec's own deadline, and a genuinely dead guest fails a
// few seconds in rather than pinning the connection for the multi-minute exec cap.
// The transient/terminal split lives HERE, not at the state layer: the row was
// already resolved ACTIVE-and-owned before the driver ran, so a not-owned or
// absent session is refused ABOVE this call (a fast, driver-never-reached 404) and
// never enters this poll — the wait is spent only on a guest that is provably ours
// and provably coming up, so no timing signal leaks about a foreign or absent row.
func dialWithColdWait(ctx context.Context, socketPath string, minter dial.Minter) (*dial.Channel, error) {
	waitCtx, cancel := context.WithTimeout(ctx, dialWaitBudget)
	defer cancel()

	for {
		// Each dial is bounded by waitCtx so a single hanging connect/handshake cannot
		// outlive the cold-wait budget; the returned channel keeps no reference to this
		// ctx — the handshake and drive that follow use the exec's own full deadline.
		ch, err := dial.DialUDS(waitCtx, socketPath, minter)
		if err == nil {
			return ch, nil
		}
		// Terminal error, or the wait budget / caller deadline is spent: surface it.
		if !isTransientDialError(err) || waitCtx.Err() != nil {
			return nil, err
		}
		// Provably-transient: the socket is not up yet. Sleep a poll tick (or bail
		// the instant the wait budget or the caller's context is done) and re-dial.
		select {
		case <-waitCtx.Done():
			return nil, err
		case <-time.After(redialInterval):
		}
	}
}

// isTransientDialError reports whether a dial failure is the not-yet-ready cold
// shape worth re-dialling: a connect(2) that found no socket file (ENOENT) or a
// bound-but-not-accepting listener (ECONNREFUSED). errors.Is walks the wrapped
// chain the websocket-over-UDS dialer builds (fmt.Errorf %w → *url.Error →
// *net.OpError → *os.SyscallError → syscall.Errno), so the classification reaches
// the real errno regardless of the wrapping. A cancelled/expired context is NOT
// transient here — it is the caller's own bound and must surface at once.
func isTransientDialError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
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
