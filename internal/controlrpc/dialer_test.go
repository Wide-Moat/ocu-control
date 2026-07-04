// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlrpc_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/controlrpc"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// newTestDialer builds a Dialer over a real Signer (the narrow execMinter) on a
// FakeClock, so the dial mints a genuine per-dial exec JWT. The mint must succeed
// for the dial to reach the wire, so a real Signer keeps the test honest end to
// end rather than stubbing the mint.
func newTestDialer(t *testing.T, timeout time.Duration) *controlrpc.Dialer {
	t.Helper()
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))
	signer := newControlSigner(t, clk)
	return controlrpc.NewDialer(signer, timeout)
}

// guestStub is a minimal in-test guest: it listens on the host-dialled control
// UDS, reads one Request frame, and replies with the configured Reply. It stands
// in for the in-guest control-RPC endpoint so the dial exercises the real wire.
type guestStub struct {
	ln    net.Listener
	reply controlrpc.Reply
	wg    sync.WaitGroup
}

// startGuestStub binds a listener at sockPath and serves one connection,
// answering with reply. It returns the stub so the caller can stop it.
func startGuestStub(t *testing.T, sockPath string, reply controlrpc.Reply) *guestStub {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen %q: %v", sockPath, err)
	}
	g := &guestStub{ln: ln, reply: reply}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		conn, aerr := ln.Accept()
		if aerr != nil {
			return // listener closed; nothing to serve
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, derr := controlrpc.DecodeRequest(bufio.NewReader(conn)); derr != nil {
			return
		}
		_ = controlrpc.EncodeReply(conn, g.reply)
	}()
	return g
}

func (g *guestStub) stop() {
	_ = g.ln.Close()
	g.wg.Wait()
}

// hostOwnedSockDir creates the real handoff sock layout — a 0777 sock LEAF inside a
// 0700 host-owned ROOT — and returns the leaf (what the dialer is handed). The leaf
// is world-writable by design so the CapDrop guest can bind(2); the 0700 root is
// the trust wall the gate checks. It is rooted in a SHORT base (not the long nested
// t.TempDir) because a Unix socket path has a platform cap (~104 bytes on Darwin),
// and t.TempDir's deep path overruns it.
func hostOwnedSockDir(t *testing.T) string {
	t.Helper()
	root := shortDir(t, 0o700)
	leaf := filepath.Join(root, "sock")
	if err := os.Mkdir(leaf, 0o777); err != nil {
		t.Fatalf("mkdir sock leaf: %v", err)
	}
	if err := os.Chmod(leaf, 0o777); err != nil {
		t.Fatalf("chmod sock leaf: %v", err)
	}
	return leaf
}

// shortDir creates a short-pathed temp directory at mode and registers cleanup, so
// a Unix socket bound inside it stays under the platform's sun_path length cap.
func shortDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocurpc-*")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// Re-assert the mode against a permissive umask so the gate sees exactly it.
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod short dir: %v", err)
	}
	return dir
}

// TestDialShutdownAccepted is the real-UDS integration happy path: the host dials
// a guest stub over a real 0700 host-owned UDS and gets ShutdownAccepted (returned
// as nil — advisory acknowledgement, not a completion claim). Gated: skipped where
// a real UDS bind is not available.
func TestDialShutdownAccepted(t *testing.T) {
	skipIfNoUDS(t)
	dir := hostOwnedSockDir(t)
	sockPath := filepath.Join(dir, "control.sock")
	stub := startGuestStub(t, sockPath, controlrpc.Reply{Accepted: &controlrpc.ShutdownAccepted{}})
	defer stub.stop()

	d := newTestDialer(t, 2*time.Second)
	if err := d.Shutdown(context.Background(), dir, "ocu-sess-abc"); err != nil {
		t.Fatalf("Shutdown over 0700 UDS: want nil (accepted), got %v", err)
	}
}

// TestDialControlErrorNonAuthoritative asserts a guest ControlError reply is
// surfaced as a typed, non-nil error (the caller can branch) but is
// NON-AUTHORITATIVE: the dial returns ErrControlError, and the teardown caller
// proceeds regardless.
func TestDialControlErrorNonAuthoritative(t *testing.T) {
	skipIfNoUDS(t)
	dir := hostOwnedSockDir(t)
	sockPath := filepath.Join(dir, "control.sock")
	reply := controlrpc.Reply{Error: &controlrpc.ControlError{
		BoundedReason: controlrpc.BoundedReason{ReasonCode: "GUEST_BUSY"},
	}}
	stub := startGuestStub(t, sockPath, reply)
	defer stub.stop()

	d := newTestDialer(t, 2*time.Second)
	err := d.Shutdown(context.Background(), dir, "ocu-sess-abc")
	if !errors.Is(err, controlrpc.ErrControlError) {
		t.Fatalf("ControlError reply: want ErrControlError, got %v", err)
	}
}

// TestDialRefusesNon0700Dir asserts a sock layout whose ROOT parent is NOT 0700
// host-owned (here, group/other-readable) is refused by the host-owned gate BEFORE
// any connect(2), even though a live listener is bound: the traversal wall is the
// root, so a loose root means a non-host peer could traverse in and plant a socket,
// and the dial is dropped before any frame is parsed (the v1 host-only-at-accept
// realization). The leaf's own 0777 mode is intended and never the reason.
func TestDialRefusesNon0700Dir(t *testing.T) {
	skipIfNoUDS(t)
	root := shortDir(t, 0o755) // loose ROOT
	dir := filepath.Join(root, "sock")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("mkdir sock leaf: %v", err)
	}
	sockPath := filepath.Join(dir, "control.sock")
	// Bind a real listener so the refusal is the GATE, not a missing socket.
	stub := startGuestStub(t, sockPath, controlrpc.Reply{Accepted: &controlrpc.ShutdownAccepted{}})
	defer stub.stop()

	d := newTestDialer(t, 2*time.Second)
	err := d.Shutdown(context.Background(), dir, "ocu-sess-abc")
	if !errors.Is(err, controlrpc.ErrSockDirGate) {
		t.Fatalf("loose root: want ErrSockDirGate, got %v", err)
	}
}

// TestDialRefusesMissingDir asserts a missing sock dir fails the gate (not a raw
// dial error), so the advisory dial never reaches connect(2) on a path that does
// not exist.
func TestDialRefusesMissingDir(t *testing.T) {
	d := newTestDialer(t, time.Second)
	err := d.Shutdown(context.Background(), filepath.Join(t.TempDir(), "absent"), "ocu-sess-abc")
	if !errors.Is(err, controlrpc.ErrSockDirGate) {
		t.Fatalf("missing sock dir: want ErrSockDirGate, got %v", err)
	}
}

// TestDialRefusesEmptyContainerName asserts the dial refuses an empty
// host-attested container_name (the exec mint subject must be present).
func TestDialRefusesEmptyContainerName(t *testing.T) {
	dir := hostOwnedSockDir(t)
	d := newTestDialer(t, time.Second)
	err := d.Shutdown(context.Background(), dir, "")
	if !errors.Is(err, cred.ErrMintIdentity) {
		t.Fatalf("empty container_name: want ErrMintIdentity, got %v", err)
	}
}

// skipIfNoUDS skips a test that needs a real Unix-domain-socket bind when the
// platform cannot provide one (the bind path length or the platform itself). The
// integration tests are gated on a successful probe bind, mirroring the design's
// "gated, t.Skip otherwise" requirement.
func skipIfNoUDS(t *testing.T) {
	t.Helper()
	probe := filepath.Join(shortDir(t, 0o700), "probe.sock")
	ln, err := net.Listen("unix", probe)
	if err != nil {
		t.Skipf("real UDS bind unavailable on this platform: %v", err)
	}
	_ = ln.Close()
}
