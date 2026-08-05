// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package guestexec

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// startStallingGuest binds exec.sock, ACCEPTS every connection, and then holds it
// open without ever speaking. This is the one dial outcome the cold-wait tests do
// not otherwise cover: TestDriverExecWaitsForColdSocket and
// TestDriverExecBoundsColdWait both exercise a socket nothing is listening on, and
// TestDriverExecFastFailsOnTerminalDialError exercises an already-cancelled caller.
// A stalling peer sits between the two conditions isTransientDialError re-dials —
// the socket file exists (no ENOENT) and something accepts (no ECONNREFUSED) — yet
// the upgrade never completes.
//
// The returned counter is how a caller distinguishes one attempt from several.
func startStallingGuest(t *testing.T, sockDir string) *atomic.Int64 {
	t.Helper()
	var accepts atomic.Int64
	ln, err := net.Listen("unix", filepath.Join(sockDir, execSockName))
	if err != nil {
		t.Fatalf("bind stalling exec.sock: %v", err)
	}
	held := make(chan net.Conn, 16)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			accepts.Add(1)
			// Hold it open and stay silent: no upgrade, no close. A close would
			// surface as a different error class and stop testing the stall.
			select {
			case held <- c:
			default:
				_ = c.Close()
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case c := <-held:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return &accepts
}

// TestDriverExecRetriesAStalledHandshakeWithinTheDialBudget pins that a guest which
// accepts and then goes silent is re-dialled rather than allowed to spend the whole
// cold window in one attempt, and that the re-dialling stays bounded.
//
// The accept count is the load-bearing assertion. Without dialAttemptBudget the
// stall produced exactly ONE accept: a single dial consumed the entire budget, so
// the re-dial poll was unreachable for any failure that takes time — it could only
// ever fire for errors that return instantly. More than one accept is the proof
// that the poll now runs for this shape. The count is bounded above as well,
// because a dial that stopped honouring the attempt budget would spin and show a
// far larger number.
//
// Two clocks bound this exec: the caller's exec deadline (TimeoutS, 30s here) and
// the cold-wait budget (dialWaitBudget, 5s). They are set an order of magnitude
// apart on purpose — with both near 3s a pass proves nothing about which one did
// the bounding, and only the dial budget can explain a return near 5s.
//
// The elapsed upper bound is an absolute 15s rather than a multiple of
// dialWaitBudget: a bound expressed in terms of the constant under test moves with
// it, so raising the budget to a minute would keep such a test green. 15s is fixed
// well below the 30s exec deadline, so it reddens if the dial ever stops being
// bounded separately from the caller's deadline.
func TestDriverExecRetriesAStalledHandshakeWithinTheDialBudget(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	sockDir := shortSockDir(t)
	accepts := startStallingGuest(t, sockDir)

	d := NewDriver(signer)
	start := time.Now()
	_, err := d.Exec(context.Background(), sockDir, "ocu-session-stalled-hs",
		Request{Argv: []string{"true"}, TimeoutS: 30})
	elapsed := time.Since(start)
	n := accepts.Load()

	if err == nil {
		t.Fatal("Exec against a guest that accepts and never speaks = nil error; want a refusal")
	}
	// Anti-vacuity: a return that is too FAST means the dial never reached the
	// stalling peer at all (a failed bind surfaces as ENOENT in milliseconds), and
	// every assertion below would then be measuring the wrong thing.
	if elapsed < 4*time.Second {
		t.Fatalf("Exec returned in %v after %d accepts; too fast to have spent the cold "+
			"window on a stalling peer, so this test proved nothing", elapsed, n)
	}
	if elapsed > 15*time.Second {
		t.Errorf("Exec took %v against a stalling handshake; the dial must stay bounded by "+
			"its own cold-wait budget rather than running to the caller's exec deadline", elapsed)
	}
	if n < 2 {
		t.Errorf("stalling listener saw %d accepts; want more than 1 — one attempt that "+
			"consumes the whole budget leaves nothing to re-dial into, which is exactly "+
			"what dialAttemptBudget exists to prevent", n)
	}
	// Absolute, not dialWaitBudget/dialAttemptBudget: a ceiling computed from the
	// constants under test moves with them, so shrinking the attempt budget would
	// raise the ceiling by exactly as much and the spin would stay green. The
	// shipped pair yields three full attempts plus a partial; 8 leaves room for
	// scheduling jitter and still sits far below any spin.
	const maxAttempts = 8
	if n > maxAttempts {
		t.Errorf("stalling listener saw %d accepts; want at most %d — more means an attempt "+
			"is no longer bounded by dialAttemptBudget and the poll is spinning", n, maxAttempts)
	}
	t.Logf("stalled handshake: err=%v elapsed=%v accepts=%d", err, elapsed, n)
}
