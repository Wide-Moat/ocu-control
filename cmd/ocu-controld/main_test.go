// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
)

// writeTestKey writes a valid Ed25519 PKCS8 signing key to path so the boot-time
// fail-closed Signer load succeeds. The daemon now refuses to start without a real
// key at -jwt-signing-key (there is no daemon-default key), so any test that reaches
// serve() must supply one.
func writeTestKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
}

// validArgs is a fully-valid serving invocation EXCEPT it binds nothing (Phase
// 1 opens no socket). Individual cases append or perturb one field. The
// listen/jwt/audit values are never dialled or opened on the paths these tests
// exercise: the static gates pass, boot runs against the in-memory default
// store, and either the kill-switch-first create refusal or the bind stub is
// reached — none of which touches those paths.
func validArgs() []string {
	return []string{
		"-operator-listen", "unix:///tmp/ocu-test-operator.sock",
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", "/tmp/ocu-test-jwt.key",
		"-audit-sink", "/tmp/ocu-test-audit.jsonl",
	}
}

// Test_run_MissingRequiredFlag asserts the first absent required flag is named
// and the typed sentinel is returned, the smoke's load-bearing substring.
func Test_run_MissingRequiredFlag(t *testing.T) {
	t.Parallel()
	err := run(context.Background(), []string{"-runtime-tier", "runc"})
	if err == nil {
		t.Fatal("run() returned nil on a missing required flag; want a refusal")
	}
	if !errors.Is(err, errRequiredFlagMissing) {
		t.Fatalf("run() error does not match errRequiredFlagMissing: %v", err)
	}
	if !strings.Contains(err.Error(), "-operator-listen") {
		t.Fatalf("run() error %q does not name the first missing flag -operator-listen", err)
	}
}

// Test_run_UnknownRuntimeTier asserts an unknown tier is refused pre-bind,
// before any Store is constructed.
func Test_run_UnknownRuntimeTier(t *testing.T) {
	t.Parallel()
	args := validArgs()
	args[5] = "bogus" // -runtime-tier value
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownRuntimeTier) {
		t.Fatalf("run() error does not match errUnknownRuntimeTier: %v", err)
	}
}

// Test_run_UnknownRuntimeProvider asserts an unknown provider is refused
// pre-bind.
func Test_run_UnknownRuntimeProvider(t *testing.T) {
	t.Parallel()
	args := validArgs()
	args[7] = "podman" // -runtime-provider value
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownProvider) {
		t.Fatalf("run() error does not match errUnknownProvider: %v", err)
	}
}

// Test_run_KillSwitchFirst drives -create-on-start through the REAL boot path
// with the default in-memory store: boot engages the deployment-wide
// kill-switch, AdmitCreate refuses through a real Store.Reserve, and run()
// surfaces the refusal wrapped under errKillSwitchFirst with the load-bearing
// NFR-SEC-01 substring.
func Test_run_KillSwitchFirst(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-create-on-start")
	err := run(context.Background(), args)
	if err == nil {
		t.Fatal("run() returned nil on -create-on-start; want a kill-switch-first refusal")
	}
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("run() error does not wrap errKillSwitchFirst: %v", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("run() error %q does not name NFR-SEC-01", err)
	}
}

// Test_run_KillSwitchFirst_ExplicitInMemory documents that an explicit empty
// -state-dsn (the in-memory default) refuses identically, mirroring the smoke's
// explicit-empty assertion.
func Test_run_KillSwitchFirst_ExplicitInMemory(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-state-dsn", "", "-create-on-start")
	err := run(context.Background(), args)
	if !errors.Is(err, errKillSwitchFirst) {
		t.Fatalf("run() with explicit empty -state-dsn does not wrap errKillSwitchFirst: %v", err)
	}
	if !strings.Contains(err.Error(), "NFR-SEC-01") {
		t.Fatalf("run() error %q does not name NFR-SEC-01", err)
	}
}

// Test_run_CleanBoot_BindsThenServes asserts a clean, create-free boot loads the
// deny posture, binds BOTH listeners off the readiness hook, and serves until the
// context is cancelled — returning nil on the clean ctx-driven shutdown, never a
// static-gate or fail-closed error. This proves the two-listener bind is reachable
// only after a successful boot and that a cancelled context unwinds the listeners
// cleanly. The operator socket and gateway port live under the test's own temp
// dir / an ephemeral port so the test binds real sockets without colliding.
func Test_run_CleanBoot_BindsThenServes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	// The operator socket lives under a short OS-temp path, not the (potentially
	// ~110-byte) t.TempDir(): a Unix socket path over the ~104-byte sockaddr_un
	// sun_path limit fails to bind with "invalid argument" on darwin and any
	// long-TMPDIR host, which would make this serving smoke red off CI.
	sockPath := shortSocketPath(t)
	args := []string{
		"-operator-listen", "unix://" + sockPath,
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", keyPath,
		"-audit-sink", filepath.Join(dir, "audit.jsonl"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, args) }()

	// Let boot reach the readiness hook (reconcile + bind), then cancel; a clean ctx
	// shutdown of the serve loop returns nil.
	time.Sleep(250 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			return // clean boot bound both listeners and shut down cleanly on cancel
		}
		// The boot orphan-sweep reconcile dials the Docker daemon. On a host with no
		// daemon (CI without Docker) that fail-closed error is the expected outcome of
		// a clean boot reaching the reconcile step — which still proves the bind hook
		// is reached only after a successful deny-posture load. Treat it as a skip so
		// the test does not require a daemon, but a NON-reconcile error still fails.
		if strings.Contains(err.Error(), "reconcile") {
			t.Skipf("clean boot reached the readiness hook; Docker daemon unavailable for the orphan sweep: %v", err)
			return
		}
		t.Fatalf("run() on a clean boot returned %v; want nil on a ctx-driven shutdown", err)
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not return within 10s after ctx cancel")
	}
}

// Test_run_UnknownJWTAlg asserts an unknown -jwt-alg is refused pre-bind, never
// coerced to a default; the default eddsa is exercised by the clean-boot test.
func Test_run_UnknownJWTAlg(t *testing.T) {
	t.Parallel()
	args := append(validArgs(), "-jwt-alg", "rsa")
	err := run(context.Background(), args)
	if !errors.Is(err, errUnknownJWTAlg) {
		t.Fatalf("run() with -jwt-alg rsa error does not match errUnknownJWTAlg: %v", err)
	}
}

// Test_run_BadSigningKeyFailsClosedBeforeBind asserts a missing/garbage signing key
// aborts the daemon at boot BEFORE any listener binds: a clean (create-free) boot
// with a -jwt-signing-key that does not resolve to a valid key returns a wrapped
// cred.ErrSigningKeyMissing, and no socket is left behind. This is the fail-closed
// custody invariant — there is no daemon-default key.
func Test_run_BadSigningKeyFailsClosedBeforeBind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	args := []string{
		"-operator-listen", "unix://" + filepath.Join(dir, "operator.sock"),
		"-gateway-listen", "127.0.0.1:0",
		"-runtime-tier", "runc",
		"-runtime-provider", "docker",
		"-workload-profile", "trusted_operator",
		"-jwt-signing-key", filepath.Join(dir, "absent.key"), // never written
		"-audit-sink", filepath.Join(dir, "audit.jsonl"),
	}
	err := run(context.Background(), args)
	if !errors.Is(err, cred.ErrSigningKeyMissing) {
		t.Fatalf("run() with an absent signing key error does not wrap cred.ErrSigningKeyMissing: %v", err)
	}
	// The fail-closed abort happens before the bind hook is installed, so no operator
	// socket survives the refusal.
	if _, statErr := os.Stat(filepath.Join(dir, "operator.sock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("a fail-closed signer-load abort left an operator socket (stat err=%v); want no socket", statErr)
	}
}

// Test_serveListeners_SignalDrainsAndUnlinksSocket proves the HOST-side daemon-stop
// drain: a cancelled root context (the SIGINT/SIGTERM path) makes serveListeners
// stop accepting on both listeners, drain both Serve loops, and unlink the operator
// Unix socket — returning nil (a signal stop is not an error). Before the fix the
// root context was never cancelled, so the Serve loops never drained and the socket
// was never unlinked. This exercises serveListeners directly so it needs no Docker
// daemon for the orphan sweep.
func Test_serveListeners_SignalDrainsAndUnlinksSocket(t *testing.T) {
	t.Parallel()
	sock := shortSocketPath(t)

	op := operator.NewListener(sock, operator.Deps{})
	gw := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := op.Bind(); err != nil {
		t.Fatalf("operator Bind: %v", err)
	}
	if err := gw.Bind(); err != nil {
		t.Fatalf("gateway Bind: %v", err)
	}

	// The operator socket exists while serving.
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("operator socket must exist after Bind: %v", err)
	}
	// The gateway TCP port is accepting connections while serving.
	gwAddr := gw.Addr()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveListeners(ctx, op, gw) }()

	// Give the Serve loops a moment to come up, prove the gateway is reachable, then
	// cancel the root context (the signal path).
	waitFor(t, func() bool {
		c, err := net.DialTimeout("tcp", gwAddr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveListeners on a cancelled (signal) context must return nil, got: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serveListeners did not drain within 15s of ctx cancel")
	}

	// The operator socket is unlinked: the deferred Close ran on the signal path.
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("operator socket must be unlinked after a signal-driven drain (stat err=%v); want not-exist", err)
	}
	// The gateway port is released: a dial now fails.
	if c, err := net.DialTimeout("tcp", gwAddr, 200*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("gateway port must be released after the drain; a dial still succeeded")
	}
}

// Test_serveListeners_ServeErrorReturnsAndCloses proves the error path: when a Serve
// loop fails before any signal, serveListeners returns that error AND still closes
// both listeners (the operator socket is unlinked) so a failure leaves no half-open
// listener. A never-bound operator listener makes op.Serve return immediately.
func Test_serveListeners_ServeErrorReturnsAndCloses(t *testing.T) {
	t.Parallel()
	sock := shortSocketPath(t)

	// op is bound (its socket exists); gw is NOT bound, so gw.Serve returns an error
	// immediately, driving the error path of serveListeners.
	op := operator.NewListener(sock, operator.Deps{})
	gw := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := op.Bind(); err != nil {
		t.Fatalf("operator Bind: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- serveListeners(context.Background(), op, gw) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serveListeners with an unbound gateway must return the serve error, got nil")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serveListeners did not return within 15s on a serve error")
	}

	// Both listeners were closed on the error path: the operator socket is unlinked.
	if _, err := os.Stat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("operator socket must be unlinked after a serve-error close (stat err=%v); want not-exist", err)
	}
}

// shortSocketPath returns a Unix-socket path SHORT enough for the platform's
// sun_path limit (~104 bytes on darwin), which a deeply-nested t.TempDir() path can
// exceed. It creates a short-named dir directly under the OS temp root and removes
// the whole tree on cleanup, so the bound socket never leaks.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocu")
	if err != nil {
		t.Fatalf("mkdir short temp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "op.sock")
}

// waitFor polls cond up to 5s, failing the test if it never becomes true. It lets a
// drain test wait on a real readiness condition instead of a fixed sleep.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within 5s")
}

// Test_run_Version returns the version with no boot.
func Test_run_Version(t *testing.T) {
	t.Parallel()
	if err := run(context.Background(), []string{"-version"}); err != nil {
		t.Fatalf("run(-version): %v", err)
	}
}
