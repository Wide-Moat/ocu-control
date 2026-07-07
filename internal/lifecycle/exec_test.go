// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// execAttacker is a caller in a DIFFERENT namespace than testCaller, used to
// prove the not-owned addressing defence on the exec path.
var execAttacker = ingress.AuthenticatedCaller{
	Identity: state.Identity{Tenant: "tenant-b", Caller: "caller-2"},
	Channel:  ingress.ChannelGateway,
}

// recordingExecDriver captures the exec calls the Manager routes to the driver
// seam, so a test can assert the host-derived sockDir and container name reached
// it and control the returned result/error.
type recordingExecDriver struct {
	mu     sync.Mutex
	calls  []execCall
	result lifecycle.ExecResult
	err    error
}

type execCall struct {
	sockDir       string
	containerName string
	req           lifecycle.ExecRequest
}

func (d *recordingExecDriver) Exec(_ context.Context, sockDir, containerName string, req lifecycle.ExecRequest) (lifecycle.ExecResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, execCall{sockDir: sockDir, containerName: containerName, req: req})
	return d.result, d.err
}

func (d *recordingExecDriver) last() (execCall, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		return execCall{}, false
	}
	return d.calls[len(d.calls)-1], true
}

// newExecHarness builds a Manager with an exec driver wired through ManagerDeps,
// plus a live session to exec into. It returns the harness and the session hint
// the caller addresses. It mirrors newHarness but sets the ExecDriver dep.
func newExecHarness(t *testing.T, driver lifecycle.ExecDriver) (*harness, string) {
	t.Helper()
	h := newHarnessWithExec(t, driver)
	if _, err := h.mgr.Create(context.Background(), input("exec-session")); err != nil {
		t.Fatalf("create: %v", err)
	}
	return h, "exec-session"
}

// TestExecRoutesToDriverWithHostDerivedTarget pins the happy path: Exec resolves
// the caller's own row, audits the exec, and routes to the driver with the
// host-derived sock dir and the row's container name — never a body value — and
// returns the driver's result.
func TestExecRoutesToDriverWithHostDerivedTarget(t *testing.T) {
	t.Parallel()
	driver := &recordingExecDriver{result: lifecycle.ExecResult{ExitCode: 3, Stdout: []byte("out")}}
	h, hint := newExecHarness(t, driver)

	res, err := h.mgr.Exec(context.Background(), testCaller, hint, lifecycle.ExecRequest{
		Argv:     []string{"echo", "hi"},
		TimeoutS: 10,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 3 || string(res.Stdout) != "out" {
		t.Fatalf("Exec result = %+v; want the driver's result", res)
	}
	call, ok := driver.last()
	if !ok {
		t.Fatal("driver was never called")
	}
	if call.sockDir == "" {
		t.Fatal("driver sockDir is empty; want the host-derived session sock dir")
	}
	if call.containerName == "" {
		t.Fatal("driver containerName is empty; want the row's container name")
	}
	if len(call.req.Argv) != 2 || call.req.Argv[0] != "echo" {
		t.Fatalf("driver req.Argv = %v; want the request argv", call.req.Argv)
	}
}

// TestExecAuditsBeforeDriverFailClosed pins F10 fail-closed ordering: the exec
// record is emitted BEFORE the driver runs, and an audit write failure denies the
// exec — the driver is never called.
func TestExecAuditsBeforeDriverFailClosed(t *testing.T) {
	t.Parallel()
	driver := &recordingExecDriver{}
	h, hint := newExecHarness(t, driver)
	h.audit.SetFault(true, errors.New("sink down"))

	_, err := h.mgr.Exec(context.Background(), testCaller, hint, lifecycle.ExecRequest{Argv: []string{"true"}})
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Exec with a failing audit sink = %v; want ErrAuditWriteFailed", err)
	}
	if _, ok := driver.last(); ok {
		t.Fatal("driver ran despite the fail-closed audit deny")
	}
}

// TestExecEmitsActionExecRecord pins the record shape: exactly one ActionExec
// record on the addressed row's key, host-derived caller and tenant, and it is
// emitted on the gateway channel.
func TestExecEmitsActionExecRecord(t *testing.T) {
	t.Parallel()
	driver := &recordingExecDriver{result: lifecycle.ExecResult{ExitCode: 0}}
	h, hint := newExecHarness(t, driver)

	gwCaller := ingress.AuthenticatedCaller{Identity: testCaller.Identity, Channel: ingress.ChannelGateway}
	if _, err := h.mgr.Exec(context.Background(), gwCaller, hint, lifecycle.ExecRequest{Argv: []string{"true"}}); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	var execRecs []audit.Record
	for _, r := range h.audit.Records() {
		if r.Action == audit.ActionExec {
			execRecs = append(execRecs, r)
		}
	}
	if len(execRecs) != 1 {
		t.Fatalf("ActionExec records = %d; want 1", len(execRecs))
	}
	rec := execRecs[0]
	if rec.Channel != "gateway" {
		t.Fatalf("exec record channel = %q; want gateway", rec.Channel)
	}
	if rec.Caller != testCaller.Identity.Caller || rec.Tenant != testCaller.Identity.Tenant {
		t.Fatalf("exec record caller/tenant = %q/%q; want host-derived %q/%q",
			rec.Caller, rec.Tenant, testCaller.Identity.Caller, testCaller.Identity.Tenant)
	}
	if rec.Key == "" {
		t.Fatal("exec record key is empty; want the addressed row's key")
	}
}

// TestExecForeignSessionNotFound pins the addressing defence: an exec for a hint
// that addresses no row in the caller's namespace is refused (not-owned,
// indistinguishable from not-found), the driver is never called, and no exec
// record is written.
func TestExecForeignSessionNotFound(t *testing.T) {
	t.Parallel()
	driver := &recordingExecDriver{}
	h, hint := newExecHarness(t, driver)

	_, err := h.mgr.Exec(context.Background(), execAttacker, hint, lifecycle.ExecRequest{Argv: []string{"true"}})
	if err == nil {
		t.Fatal("Exec for a foreign session = nil error; want a not-owned refusal")
	}
	if _, ok := driver.last(); ok {
		t.Fatal("driver ran for a foreign session")
	}
	for _, r := range h.audit.Records() {
		if r.Action == audit.ActionExec {
			t.Fatal("an exec record was written for a foreign-session refusal")
		}
	}
}

// TestExecNotFoundBurnsNoDialWait is the negative twin of the cold-exec wait: a
// not-owned/not-found session is refused ABOVE the driver — the row lookup fails
// audience-scoped and the driver (where the bounded cold-start re-dial poll lives)
// is never reached. So the refusal is IMMEDIATE, never spending the multi-second
// dial-wait budget. This pins that the cold-start wait cannot become a timing
// oracle: a foreign or absent session cannot be distinguished from a real-but-cold
// one by how long the refusal takes, because it never enters the wait at all.
func TestExecNotFoundBurnsNoDialWait(t *testing.T) {
	t.Parallel()
	driver := &recordingExecDriver{}
	h, hint := newExecHarness(t, driver)

	start := time.Now()
	_, err := h.mgr.Exec(context.Background(), execAttacker, hint, lifecycle.ExecRequest{Argv: []string{"true"}})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Exec for a foreign session = nil error; want a not-owned refusal")
	}
	if _, ok := driver.last(); ok {
		t.Fatal("driver ran for a foreign session; the not-found path must never reach the cold-wait")
	}
	// The refusal is a synchronous lookup miss, not a dial wait: it returns in well
	// under the driver's seconds-long dial-wait budget. A generous ceiling keeps the
	// assertion non-flaky while still proving no backoff is burned.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("not-found exec refusal took %v; a not-owned session must refuse fast, never entering the cold-wait", elapsed)
	}
}
