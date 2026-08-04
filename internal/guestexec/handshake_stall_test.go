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

// TestDriverExecStalledHandshakeIsBoundedByDialBudget pins what a silent-but-
// accepting guest costs, and which of the two clocks in play stops it.
//
// Two clocks bound this exec: the caller's exec deadline (TimeoutS, 30s here) and
// the cold-wait budget dialWithColdWait imposes on the dial (dialWaitBudget, 5s).
// The test sets them an order of magnitude apart on purpose. With TimeoutS at 3s —
// the shape this test first took — both clocks fire at nearly the same moment and a
// pass proves nothing about which one did the bounding. Separating them is the
// whole point: only the dial budget can explain a return near 5s.
//
// The upper bound is written as an absolute 15s rather than a multiple of
// dialWaitBudget. A bound expressed in terms of the constant under test moves with
// it, so raising the budget to a minute would keep such a test green; 15s is fixed
// well below the 30s exec deadline, so it reddens if the dial ever stops being
// bounded separately from the caller's deadline.
//
// The accept count is a characterisation, not an aspiration. It records that the
// stall consumes the ENTIRE budget in one attempt, which is why no re-dial follows:
// by the time the error surfaces there is no budget left to retry into. Widening
// isTransientDialError alone therefore cannot produce a second attempt — verified
// by neutering both the classification and the waitCtx guard, which still yielded
// exactly one accept. A retry for this shape needs a per-attempt dial bound first.
func TestDriverExecStalledHandshakeIsBoundedByDialBudget(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	sockDir := shortSockDir(t)
	accepts := startStallingGuest(t, sockDir)

	d := NewDriver(signer)
	start := time.Now()
	_, err := d.Exec(context.Background(), sockDir, "ocu-session-stalled-hs",
		Request{Argv: []string{"true"}, TimeoutS: 30})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Exec against a guest that accepts and never speaks = nil error; want a refusal")
	}
	// Anti-vacuity: a return that is too FAST means the dial never reached the
	// stalling peer at all (a failed bind surfaces as ENOENT in milliseconds), and
	// every assertion below would then be measuring the wrong thing.
	if elapsed < 4*time.Second {
		t.Fatalf("Exec returned in %v; too fast to have stalled — the dial cannot have "+
			"reached the accepting-but-silent peer, so this test proved nothing", elapsed)
	}
	if elapsed > 15*time.Second {
		t.Errorf("Exec took %v against a stalling handshake; the dial must stay bounded by "+
			"its own cold-wait budget rather than running to the caller's exec deadline", elapsed)
	}
	if n := accepts.Load(); n != 1 {
		t.Errorf("stalling listener saw %d accepts; want exactly 1 — the single attempt "+
			"consumes the whole cold-wait budget, leaving nothing to re-dial into", n)
	}
	t.Logf("stalled handshake: err=%v elapsed=%v accepts=%d", err, elapsed, accepts.Load())
}
