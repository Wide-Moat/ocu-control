// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// serveHealthz binds a real Unix socket and serves the given handler at /healthz,
// returning the socket path. It mirrors the operator listener's HTTP-over-UDS
// transport so the health-check client is exercised against the same wire shape the
// daemon serves, with no daemon boot. The server is torn down on test cleanup.
func serveHealthz(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	socket := shortSocketPath(t)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix %q: %v", socket, err)
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", handler)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}

	served := make(chan struct{})
	go func() {
		close(served)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	<-served
	waitHealthzReady(t, socket)
	return socket
}

// waitHealthzReady polls the socket until a connection succeeds, so a probe test
// does not race the Serve goroutine's accept loop.
func waitHealthzReady(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("healthz socket %q did not accept within the deadline", socket)
}

// Test_healthCheck_GreenWhen200 proves the client returns nil when /healthz answers
// 200, so the probe exits 0 against a ready daemon.
func Test_healthCheck_GreenWhen200(t *testing.T) {
	t.Parallel()
	socket := serveHealthz(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	if err := healthCheck(context.Background(), "unix://"+socket); err != nil {
		t.Fatalf("healthCheck against a 200 /healthz = %v, want nil (exit 0)", err)
	}
}

// Test_healthCheck_GreenWhenBarePath proves -operator-listen may be a bare socket
// path (no unix:// scheme), exactly as socketPathOf accepts on the serving side.
func Test_healthCheck_GreenWhenBarePath(t *testing.T) {
	t.Parallel()
	socket := serveHealthz(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if err := healthCheck(context.Background(), socket); err != nil {
		t.Fatalf("healthCheck against a bare-path socket = %v, want nil", err)
	}
}

// Test_healthCheck_RedWhenNon200 proves a non-200 (the readiness enum not flipped:
// 503) is a non-nil error, so the probe exits non-zero against a not-ready daemon.
func Test_healthCheck_RedWhenNon200(t *testing.T) {
	t.Parallel()
	socket := serveHealthz(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready: loading deny posture"))
	})
	if err := healthCheck(context.Background(), "unix://"+socket); err == nil {
		t.Fatal("healthCheck against a 503 /healthz = nil, want a non-nil error (exit non-zero)")
	}
}

// Test_healthCheck_RedWhenNoListener proves a refused dial (no daemon bound on the
// socket) is a non-nil error: the probe is red when nothing is serving.
func Test_healthCheck_RedWhenNoListener(t *testing.T) {
	t.Parallel()
	// A socket path under a temp dir that was never bound.
	socket := filepath.Join(t.TempDir(), "absent.sock")
	if err := healthCheck(context.Background(), "unix://"+socket); err == nil {
		t.Fatal("healthCheck against an unbound socket = nil, want a non-nil error")
	}
}

// Test_healthCheck_RedWhenNoEndpoint proves a missing -operator-listen is a non-nil
// error naming the requirement, so a probe invocation that forgets the socket flag
// fails loudly rather than dialing an empty path.
func Test_healthCheck_RedWhenNoEndpoint(t *testing.T) {
	t.Parallel()
	if err := healthCheck(context.Background(), ""); !errors.Is(err, errHealthCheckNoSocket) {
		t.Fatalf("healthCheck(\"\") = %v, want errHealthCheckNoSocket", err)
	}
}

// Test_healthCheck_RedWhenTimeout proves a daemon that accepts but never answers
// trips the bounded probe timeout into a non-nil error, so a wedged daemon is red
// rather than hanging the probe forever. The handler blocks past the probe timeout.
func Test_healthCheck_RedWhenTimeout(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	socket := serveHealthz(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})
	// A parent context far longer than the internal healthCheckTimeout, so it is the
	// probe's own bound that fires.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if err := healthCheck(ctx, "unix://"+socket); err == nil {
		t.Fatal("healthCheck against a never-answering /healthz = nil, want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("healthCheck took %v, want it bounded near healthCheckTimeout", elapsed)
	}
}

// Test_run_HealthCheck_DialsRealOperatorListener proves the END-TO-END path: a real
// operator.Listener bound on a temp socket serving the boot Sequencer's /healthz,
// then run(-health-check -operator-listen ...) returns nil once the daemon is ready.
// This is the integration the manifests rely on — the probe re-derives the socket
// from the same -operator-listen the serving daemon used.
func Test_run_HealthCheck_DialsRealOperatorListener(t *testing.T) {
	t.Parallel()
	socket := shortSocketPath(t)

	// A bare 200 handler standing in for the boot Sequencer's ready /healthz; the
	// listener's HTTP-over-UDS transport is the real one the daemon serves.
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	waitHealthzReady(t, socket)

	err = run(context.Background(), []string{"-health-check", "-operator-listen", "unix://" + socket})
	if err != nil {
		t.Fatalf("run(-health-check) against a ready listener = %v, want nil", err)
	}
}

// Test_run_HealthCheck_RedWhenNoDaemon proves run(-health-check) surfaces a non-nil
// error (exit 1 via main) when no daemon is bound — the CrashLoop-correct red.
func Test_run_HealthCheck_RedWhenNoDaemon(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(t.TempDir(), "absent.sock")
	if err := run(context.Background(), []string{"-health-check", "-operator-listen", "unix://" + socket}); err == nil {
		t.Fatal("run(-health-check) with no daemon = nil, want a non-nil error")
	}
	// The probe boots nothing, so it never creates the socket it failed to dial.
	if _, statErr := os.Stat(socket); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("health-check probe created socket %q; it must dial only, never bind", socket)
	}
}
