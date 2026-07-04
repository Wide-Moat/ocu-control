// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package guestexec

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/wire"
)

// shortSockDir makes a host-owned 0700 directory with a SHORT absolute path, so
// the exec.sock inside stays under the darwin 104-byte sun_path limit (t.TempDir
// paths overflow it).
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ge")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return dir
}

// fakeGuest is a minimal in-process exec-channel guest: it accepts the WebSocket
// on the session's exec.sock, records msg1 (the Session JWT) and msg2 (the
// ProcessConnection), replies with capabilities, streams one stdout payload, and
// exits with the configured code. It counts concurrent connections so the
// per-session serialization test can assert the peak.
type fakeGuest struct {
	exitCode   uint8
	stdout     []byte
	holdOpen   time.Duration // delay between capabilities and stdout, to overlap execs
	srv        *http.Server
	mu         sync.Mutex
	gotJWT     string
	gotConn    wire.ProcessConnection
	inFlight   atomic.Int32
	peakOnce   sync.Mutex
	peakActive int32
}

func (g *fakeGuest) recordPeak(n int32) {
	g.peakOnce.Lock()
	defer g.peakOnce.Unlock()
	if n > g.peakActive {
		g.peakActive = n
	}
}

func (g *fakeGuest) peak() int32 {
	g.peakOnce.Lock()
	defer g.peakOnce.Unlock()
	return g.peakActive
}

func (g *fakeGuest) lastHandshake() (string, wire.ProcessConnection) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gotJWT, g.gotConn
}

// startFakeGuest serves the fake guest on sockDir/exec.sock.
func startFakeGuest(t *testing.T, sockDir string, g *fakeGuest) {
	t.Helper()
	sockPath := filepath.Join(sockDir, "exec.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	g.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx := r.Context()

		// msg1: the compact Session JWT as a text frame. The concurrency window
		// the serialization test measures opens HERE (a live handshake) and closes
		// after the terminal frame — not on handler entry/exit, because a hijacked
		// WebSocket handler outlives the client close on its final wait.
		_, jwtFrame, err := conn.Read(ctx)
		if err != nil {
			return
		}
		n := g.inFlight.Add(1)
		g.recordPeak(n)
		// msg2: the bare ProcessConnection.
		_, connFrame, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var pc wire.ProcessConnection
		if err := json.Unmarshal(connFrame, &pc); err != nil {
			return
		}
		g.mu.Lock()
		g.gotJWT = string(jwtFrame)
		g.gotConn = pc
		g.mu.Unlock()

		// Drain client frames (keepalives, stdin announces) in the background so
		// the channel's writers never block the scripted server side; the drain
		// erroring out is the observable "client closed" signal.
		drainDone := make(chan struct{})
		go func() {
			defer close(drainDone)
			for {
				if _, _, err := conn.Read(ctx); err != nil {
					return
				}
			}
		}()

		write := func(v any) bool {
			b, err := json.Marshal(v)
			if err != nil {
				return false
			}
			return conn.Write(ctx, websocket.MessageText, b) == nil
		}
		if !write(wire.ServerMessage{ConnectionCapabilities: &wire.ConnectionCapabilities{}}) {
			return
		}
		if !write(wire.ServerMessage{ProcessCreated: &wire.Null{}}) {
			return
		}
		if g.holdOpen > 0 {
			time.Sleep(g.holdOpen)
		}
		if len(g.stdout) > 0 {
			if !write(wire.ServerMessage{ExpectStdOut: &wire.Null{}}) {
				return
			}
			if conn.Write(ctx, websocket.MessageBinary, g.stdout) != nil {
				return
			}
			if !write(wire.ServerMessage{StdOutEOF: &wire.Null{}}) {
				return
			}
		}
		_ = write(wire.ServerMessage{ProcessExited: &wire.ProcessExited{Code: g.exitCode}})
		g.inFlight.Add(-1)
		// Hold the socket open until the client closes (the drain errors out), so
		// DriveExec reads the terminal frame before any close race.
		<-drainDone
	})}
	go func() { _ = g.srv.Serve(ln) }()
	t.Cleanup(func() { _ = g.srv.Close() })
}

// TestDriverExecRunsOneProcessEndToEnd drives one exec through the REAL dial +
// handshake + drive path against the fake guest and pins the whole contract: the
// Session JWT is container-bound and verifies against the signing key, msg2
// carries the command and the expected container name, and the result carries
// the guest's exit code and stdout.
func TestDriverExecRunsOneProcessEndToEnd(t *testing.T) {
	t.Parallel()
	signer, pub := newTestSigner(t)
	sockDir := shortSockDir(t)
	guest := &fakeGuest{exitCode: 7, stdout: []byte("hello-from-guest")}
	startFakeGuest(t, sockDir, guest)

	d := NewDriver(signer)
	res, err := d.Exec(context.Background(), sockDir, "ocu-session-ctr-9", Request{
		Argv:     []string{"echo", "hi"},
		TimeoutS: 10,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("ExitCode = %d; want 7", res.ExitCode)
	}
	if got := string(res.Stdout); got != "hello-from-guest" {
		t.Fatalf("Stdout = %q; want the guest payload", got)
	}
	if res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("truncated flags = %v/%v; want false/false", res.StdoutTruncated, res.StderrTruncated)
	}

	rawJWT, pc := guest.lastHandshake()
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(rawJWT, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"EdDSA"})); err != nil {
		t.Fatalf("msg1 is not a verifiable exec JWT: %v", err)
	}
	if sub, _ := claims["sub"].(string); sub != "ocu-session-ctr-9" {
		t.Fatalf("msg1 sub = %q; want the container name", sub)
	}
	if pc.CreateReq == nil || pc.CreateReq.Cmd != "echo" || len(pc.CreateReq.Args) != 1 || pc.CreateReq.Args[0] != "hi" {
		t.Fatalf("msg2 CreateReq = %+v; want cmd=echo args=[hi]", pc.CreateReq)
	}
	if pc.ExpectedContainerName == nil || *pc.ExpectedContainerName != "ocu-session-ctr-9" {
		t.Fatalf("msg2 expected_container_name = %v; want the container name", pc.ExpectedContainerName)
	}
	if pc.ProcessId == "" {
		t.Fatal("msg2 process_id is empty")
	}
}

// TestDriverExecRefusesLooseSockDir pins the pre-connect gate on the Exec path: a
// group-accessible sock dir is refused with ErrSockDirGate and the guest is never
// dialled.
func TestDriverExecRefusesLooseSockDir(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	sockDir := shortSockDir(t)
	guest := &fakeGuest{exitCode: 0}
	startFakeGuest(t, sockDir, guest)
	if err := os.Chmod(sockDir, 0o750); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	d := NewDriver(signer)
	_, err := d.Exec(context.Background(), sockDir, "ctr", Request{Argv: []string{"true"}})
	if !errors.Is(err, ErrSockDirGate) {
		t.Fatalf("Exec on loose sock dir = %v; want ErrSockDirGate", err)
	}
	if jwtGot, _ := guest.lastHandshake(); jwtGot != "" {
		t.Fatal("guest saw a handshake despite the gate refusal")
	}
}

// TestDriverExecRefusesEmptyArgv pins the argument precondition: no command, no
// dial.
func TestDriverExecRefusesEmptyArgv(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	d := NewDriver(signer)
	if _, err := d.Exec(context.Background(), shortSockDir(t), "ctr", Request{}); err == nil {
		t.Fatal("Exec with empty argv = nil error; want refusal")
	}
}

// TestDriverExecSerializesPerSession pins NFR-IC-05: two concurrent Execs against
// the SAME session socket never overlap on the guest — the fake guest's peak
// concurrent connection count stays 1 while both execs complete.
func TestDriverExecSerializesPerSession(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	sockDir := shortSockDir(t)
	guest := &fakeGuest{exitCode: 0, stdout: []byte("x"), holdOpen: 150 * time.Millisecond}
	startFakeGuest(t, sockDir, guest)

	d := NewDriver(signer)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = d.Exec(context.Background(), sockDir, "ctr-serial", Request{
				Argv:     []string{"true"},
				TimeoutS: 10,
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Exec %d: %v", i, err)
		}
	}
	if p := guest.peak(); p != 1 {
		t.Fatalf("peak concurrent guest connections = %d; want 1 (serialized per session)", p)
	}
}

// TestDriverExecCapsStdout pins the per-stream output bound (05-SS): a guest
// payload past the cap is truncated to the cap with the truncated flag set, and
// the exec still completes with its real exit code.
func TestDriverExecCapsStdout(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	sockDir := shortSockDir(t)
	guest := &fakeGuest{exitCode: 0, stdout: []byte(strings.Repeat("A", 100))}
	startFakeGuest(t, sockDir, guest)

	d := NewDriver(signer)
	d.stdioCap = 64 // test-tightened; the production default is 8 MiB
	res, err := d.Exec(context.Background(), sockDir, "ctr-cap", Request{
		Argv:     []string{"true"},
		TimeoutS: 10,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(res.Stdout) != 64 {
		t.Fatalf("len(Stdout) = %d; want the 64-byte cap", len(res.Stdout))
	}
	if !res.StdoutTruncated {
		t.Fatal("StdoutTruncated = false; want true past the cap")
	}
	if res.ExitCode != 0 {
		t.Fatalf("ExitCode = %d; want 0 (truncation must not fail the exec)", res.ExitCode)
	}
}

// TestEffectiveTimeoutClampsToTotalCap pins D-03: a requested timeout above the
// 5-minute total cap is clamped down, zero takes the cap, and a sane request
// passes through.
func TestEffectiveTimeoutClampsToTotalCap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   uint32
		want time.Duration
	}{
		{0, 5 * time.Minute},
		{10, 10 * time.Second},
		{301, 5 * time.Minute},
		{86400, 5 * time.Minute},
	}
	for _, tc := range cases {
		if got := effectiveTimeout(tc.in); got != tc.want {
			t.Fatalf("effectiveTimeout(%d) = %v; want %v", tc.in, got, tc.want)
		}
	}
}
