// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// Tests for the dependency-free sd_notify helper.
//
// The cross-platform proof is the filesystem path-form harness (tests 1-3): a
// real unixgram socket the test listens on, NOTIFY_SOCKET pointed at its path, and
// an assertion on the EXACT datagram bytes the helper writes. The abstract-namespace
// form (test 4) is a Linux-only socket feature and SKIPs on other platforms.
//
// The READY-after-both-bind ORDERING is proven by inspection of the wiring rather
// than a daemon test: notifyReady() is the last statement of the SetOnReady hook in
// main.go, placed after both opListener.Bind() and gwListener.Bind() succeed, and
// the boot Sequencer invokes that hook only after readiness flips ready. The helper
// tests below plus that wiring placement are the stated proof for ordering.
//
// The NOTIFY_SOCKET-mutating tests use t.Setenv, which fails the test if run under
// t.Parallel — so they intentionally do not call t.Parallel and run serially.
package main

import (
	"net"
	"runtime"
	"testing"
	"time"
)

// listenNotify creates a filesystem unixgram socket under a short temp dir, points
// NOTIFY_SOCKET at it, and returns the receiving connection. The caller calls a
// notify wrapper, then reads the datagram off the returned conn.
func listenNotify(t *testing.T) *net.UnixConn {
	t.Helper()
	path := shortSocketPath(t)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unixgram %q: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	return conn
}

// readDatagram reads one datagram off the listening conn with a generous deadline
// so a slow CI box does not false-RED, and returns the exact bytes received.
func readDatagram(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	return string(buf[:n])
}

// Test_sdNotify_ReadyDatagramReceived asserts notifyReady() writes exactly
// "READY=1" to the NOTIFY_SOCKET datagram socket.
func Test_sdNotify_ReadyDatagramReceived(t *testing.T) {
	conn := listenNotify(t)
	notifyReady()
	if got := readDatagram(t, conn); got != "READY=1" {
		t.Fatalf("notifyReady wrote %q, want %q", got, "READY=1")
	}
}

// Test_sdNotify_StoppingDatagramReceived asserts notifyStopping() writes exactly
// "STOPPING=1" to the NOTIFY_SOCKET datagram socket.
func Test_sdNotify_StoppingDatagramReceived(t *testing.T) {
	conn := listenNotify(t)
	notifyStopping()
	if got := readDatagram(t, conn); got != "STOPPING=1" {
		t.Fatalf("notifyStopping wrote %q, want %q", got, "STOPPING=1")
	}
}

// Test_sdNotify_UnsetIsNoOp asserts that with NOTIFY_SOCKET unset the helper is a
// silent no-op: it returns nil without dialing and never blocks or panics. To make
// "no-op" observable rather than vacuously true, it stands up a real listening socket
// FIRST, then blanks NOTIFY_SOCKET to the empty string: the unset guard must
// short-circuit before any address resolution, so NO datagram ever reaches the live
// listener. If the empty-guard early-return is inverted so the unset case proceeds to
// resolve/dial the address, the helper observably reaches the dial path — surfaced by
// the WARN it logs and, under the PROOF-2 mutation that also propagates the dial
// error, by a non-nil return that fails the assertion below.
//
// The belt-and-braces cases then set an unreachable path and a malformed value to
// confirm the helper still returns nil even when the dial fails (best-effort, never
// fatal).
func Test_sdNotify_UnsetIsNoOp(t *testing.T) {
	// A live listener exists, but NOTIFY_SOCKET is then blanked to empty: the unset
	// guard must win and nothing may be delivered to this socket.
	conn := listenNotify(t)       // sets NOTIFY_SOCKET to the live socket path...
	t.Setenv("NOTIFY_SOCKET", "") // ...which we blank out: the guard must short-circuit.

	if err := sdNotify("READY=1"); err != nil {
		t.Fatalf("sdNotify with NOTIFY_SOCKET unset returned %v, want nil", err)
	}
	// No datagram may have been sent: with a short deadline the read must time out.
	if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 256)
	if n, _, err := conn.ReadFromUnix(buf); err == nil {
		t.Fatalf("sdNotify with NOTIFY_SOCKET unset delivered a datagram %q; want a silent no-op (no dial, no send)", string(buf[:n]))
	}

	// Best-effort: a set-but-unreachable socket must still not fail the daemon.
	t.Setenv("NOTIFY_SOCKET", shortSocketPath(t))
	if err := sdNotify("READY=1"); err != nil {
		t.Fatalf("sdNotify with an unreachable NOTIFY_SOCKET returned %v, want nil", err)
	}

	// Malformed address (neither '/' nor '@'): swallowed as a WARN, returns nil.
	t.Setenv("NOTIFY_SOCKET", "not-a-valid-address")
	if err := sdNotify("READY=1"); err != nil {
		t.Fatalf("sdNotify with a malformed NOTIFY_SOCKET returned %v, want nil", err)
	}
}

// Test_sdNotify_AbstractNamespaceForm exercises the '@' abstract-namespace socket
// form, which systemd encodes with a leading NUL byte. Abstract-namespace unixgram
// sockets are a Linux-only kernel feature, so this SKIPs elsewhere (the path-form
// tests above are the cross-platform proof).
func Test_sdNotify_AbstractNamespaceForm(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract-namespace unixgram sockets are Linux-only; path-form tests cover other platforms")
	}
	// A process-unique abstract name; the wire form is NUL-prefixed.
	abstractName := "@ocu-control-sdnotify-test"
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "\x00" + abstractName[1:], Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen abstract unixgram: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", abstractName)

	notifyReady()
	if got := readDatagram(t, conn); got != "READY=1" {
		t.Fatalf("notifyReady (abstract) wrote %q, want %q", got, "READY=1")
	}
}
