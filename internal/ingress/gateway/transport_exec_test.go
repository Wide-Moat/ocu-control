// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fakeExecDriver records the exec calls the Manager routes to it and returns a
// scripted result, so a transport test can assert the wire body reached the
// driver and shape the response.
type fakeExecDriver struct {
	mu     sync.Mutex
	calls  []lifecycle.ExecRequest
	result lifecycle.ExecResult
}

func (d *fakeExecDriver) Exec(_ context.Context, _, _ string, req lifecycle.ExecRequest) (lifecycle.ExecResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, req)
	return d.result, nil
}

func (d *fakeExecDriver) lastArgv() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		return nil
	}
	return d.calls[len(d.calls)-1].Argv
}

// boundGatewayWithExec binds a real mTLS gateway whose Manager routes exec to the
// supplied driver, so a transport test can drive POST /v1alpha/sessions/exec over
// the wire end to end.
func boundGatewayWithExec(t *testing.T, pair mtlsPair, driver lifecycle.ExecDriver) (string, *http.Client) {
	t.Helper()
	clk := state.SystemClock()
	store := state.NewInMemory(clk)
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 16, CreateRatePerCallerPerMin: 16})
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     custodian,
		Provider:      nopProvider{},
		Clock:         clk,
		Quota:         gate,
		Handoff:       handoff.NewStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       0,
		Tier:          ocuruntime.TierRunc,
		AllowedImages: []string{"img", "ocu/sandbox:test", "registry.example/ocu-sandbox:v1"},
		ExecVerifyKey: ingressTestExecVerifyKey(),
		ExecDriver:    driver,
	})
	deps := gateway.Deps{Manager: mgr, TLSConfig: pair.serverTLS}

	l := gateway.NewListener("127.0.0.1:0", deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	addr := l.Addr()
	t.Cleanup(func() { _ = l.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve returned %v; want nil on clean shutdown", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return after context cancel")
		}
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: pair.clientTLS},
	}
	waitGatewayReady(t, client, addr)
	return addr, client
}

// createSessionForExec drives a create over the wire so a following exec addresses
// a real row, returning the session hint used.
func createSessionForExec(t *testing.T, client *http.Client, addr string) string {
	t.Helper()
	code, _ := gwPostText(t, client, addr, "/v1alpha/sessions", map[string]any{
		"session_hint": "exec-target",
		"image":        "registry.example/ocu-sandbox:v1",
	})
	if code != http.StatusCreated {
		t.Fatalf("create for exec = %d; want 201", code)
	}
	return "exec-target"
}

// TestGatewayTransportExecRunsAndReturnsResult drives POST /v1alpha/sessions/exec
// over real mTLS: the wire argv/timeout reach the driver, and the driver's exit
// code and base64 output round-trip back in the response.
func TestGatewayTransportExecRunsAndReturnsResult(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	driver := &fakeExecDriver{result: lifecycle.ExecResult{
		ExitCode:        5,
		Stdout:          []byte("stdout-bytes"),
		Stderr:          []byte("stderr-bytes"),
		StdoutTruncated: true,
	}}
	addr, client := boundGatewayWithExec(t, pair, driver)
	hint := createSessionForExec(t, client, addr)

	code, body := gwPost(t, client, addr, "/v1alpha/sessions/exec", map[string]any{
		"session_hint": hint,
		"argv":         []string{"echo", "hi"},
		"timeout_s":    10,
	})
	if code != http.StatusOK {
		t.Fatalf("exec over mTLS = %d; want 200", code)
	}
	if ec, _ := body["exit_code"].(float64); ec != 5 {
		t.Fatalf("exit_code = %v; want 5", body["exit_code"])
	}
	wantOut := base64.StdEncoding.EncodeToString([]byte("stdout-bytes"))
	if got, _ := body["stdout_b64"].(string); got != wantOut {
		t.Fatalf("stdout_b64 = %q; want %q", got, wantOut)
	}
	wantErr := base64.StdEncoding.EncodeToString([]byte("stderr-bytes"))
	if got, _ := body["stderr_b64"].(string); got != wantErr {
		t.Fatalf("stderr_b64 = %q; want %q", got, wantErr)
	}
	if tr, _ := body["stdout_truncated"].(bool); !tr {
		t.Fatalf("stdout_truncated = %v; want true", body["stdout_truncated"])
	}
	if argv := driver.lastArgv(); len(argv) != 2 || argv[0] != "echo" {
		t.Fatalf("driver argv = %v; want [echo hi]", argv)
	}
}

// TestGatewayTransportExecStdinDecoded pins the stdin_b64 decode: a base64 stdin
// payload reaches the driver as raw bytes.
func TestGatewayTransportExecStdinDecoded(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	driver := &fakeExecDriver{}
	addr, client := boundGatewayWithExec(t, pair, driver)
	hint := createSessionForExec(t, client, addr)

	code, _ := gwPost(t, client, addr, "/v1alpha/sessions/exec", map[string]any{
		"session_hint": hint,
		"argv":         []string{"cat"},
		"stdin_b64":    base64.StdEncoding.EncodeToString([]byte("piped-in")),
	})
	if code != http.StatusOK {
		t.Fatalf("exec = %d; want 200", code)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.calls) != 1 || string(driver.calls[0].Stdin) != "piped-in" {
		t.Fatalf("driver stdin = %q; want the decoded payload", driver.calls[0].Stdin)
	}
}

// TestGatewayTransportExecForeignSessionNotFound pins the addressing defence: an
// exec for a hint that addresses no row in the caller's namespace is 404 (the
// not-owned collapse), the driver is never called.
func TestGatewayTransportExecForeignSessionNotFound(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	driver := &fakeExecDriver{}
	addr, client := boundGatewayWithExec(t, pair, driver)

	code, _ := gwPost(t, client, addr, "/v1alpha/sessions/exec", map[string]any{
		"session_hint": "never-created",
		"argv":         []string{"true"},
	})
	if code != http.StatusNotFound {
		t.Fatalf("exec on a foreign session = %d; want 404", code)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.calls) != 0 {
		t.Fatalf("driver called %d times on a foreign-session exec; want 0", len(driver.calls))
	}
}

// TestGatewayTransportExecRejectsEmptyArgv pins the wire precondition: an empty
// argv is a 400 invalid argument, the driver never called.
func TestGatewayTransportExecRejectsEmptyArgv(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	driver := &fakeExecDriver{}
	addr, client := boundGatewayWithExec(t, pair, driver)
	hint := createSessionForExec(t, client, addr)

	code, _ := gwPost(t, client, addr, "/v1alpha/sessions/exec", map[string]any{
		"session_hint": hint,
		"argv":         []string{},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("exec with empty argv = %d; want 400", code)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.calls) != 0 {
		t.Fatalf("driver called on an empty-argv exec; want 0")
	}
}

// TestGatewayTransportExecRejectsBadBase64 pins the stdin_b64 decode failure: a
// malformed base64 stdin is a 400, the driver never called.
func TestGatewayTransportExecRejectsBadBase64(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	driver := &fakeExecDriver{}
	addr, client := boundGatewayWithExec(t, pair, driver)
	hint := createSessionForExec(t, client, addr)

	code, _ := gwPost(t, client, addr, "/v1alpha/sessions/exec", map[string]any{
		"session_hint": hint,
		"argv":         []string{"cat"},
		"stdin_b64":    "!!!not-base64!!!",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("exec with bad base64 stdin = %d; want 400", code)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if len(driver.calls) != 0 {
		t.Fatalf("driver called on a bad-base64 exec; want 0")
	}
}
