// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// recordingRevoker captures the step-1 revoke and returns a scripted outcome.
type recordingRevoker struct {
	called bool
	bind   runtime.EgressBinding
	out    runtime.RevokeOutcome
	err    error
}

func (r *recordingRevoker) Revoke(_ context.Context, b runtime.EgressBinding) (runtime.RevokeOutcome, error) {
	r.called = true
	r.bind = b
	return r.out, r.err
}

type recordingAuditor struct {
	recorded bool
	out      runtime.RevokeOutcome
}

func (a *recordingAuditor) RecordRevokeOutcome(_ context.Context, _ runtime.EgressBinding, o runtime.RevokeOutcome) {
	a.recorded = true
	a.out = o
}

func seededProvider(t *testing.T, tier runtime.RuntimeTier, rev Revoker, aud RevokeAuditor) (*Provider, *fakeAPI) {
	t.Helper()
	api := newFakeAPI()
	p, err := New(tier, Deps{API: api, Revoker: rev, RevokeAuditor: aud, RuntimeClass: "gvisor", Namespace: "ocu-sessions"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Seed the three session objects as if Materialize had created them.
	spec := goodSpec()
	_ = api.CreateSecret(context.Background(), buildHandoffSecret(spec, "ocu-sessions"))
	_ = api.CreateNetworkPolicy(context.Background(), buildDenyAllEgressPolicy(spec, "ocu-sessions"))
	_ = api.CreatePod(context.Background(), buildPod(spec, "gvisor", "ocu-sessions"))
	api.calls = nil // reset so teardown-order assertions are clean
	return p, api
}

func sandboxHandle() runtime.Sandbox {
	return runtime.Sandbox{
		Name:      "sess-abc",
		RuntimeID: "ocu-sess-sess-abc",
		Egress:    runtime.EgressBinding{Name: "sess-abc", FilesystemID: "fs-9"},
		Tier:      runtime.TierGvisor,
	}
}

// TestForceKill_RunsTheOrderedFinalizer is the teardown keystone: the finalizer
// runs the NFR-SEC-65 order — revoke JWT FIRST, then drop egress (policy), then
// kill the pod, then delete the secret — and every session object is gone after.
func TestForceKill_RunsTheOrderedFinalizer(t *testing.T) {
	rev := &recordingRevoker{out: runtime.RevokeMarkedDead}
	aud := &recordingAuditor{}
	p, api := seededProvider(t, runtime.TierGvisor, rev, aud)

	if err := p.Teardown().ForceKill(context.Background(), sandboxHandle()); err != nil {
		t.Fatalf("ForceKill: %v", err)
	}

	if !rev.called {
		t.Error("step 1 revoke was not called")
	}
	if rev.bind.Name != "sess-abc" {
		t.Errorf("revoke bind.Name = %q, want the host-derived session key", rev.bind.Name)
	}
	if !aud.recorded || aud.out != runtime.RevokeMarkedDead {
		t.Error("revoke outcome was not recorded as evidence")
	}

	// The kill step used grace 0 (ForceKill = no drain window).
	assertOrder(t, api.calls,
		"DeleteNetworkPolicy:ocu-net-sess-abc",
		"DeletePod:ocu-sess-sess-abc:grace=0",
		"DeleteSecret:ocu-sess-sess-abc",
	)

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.pods)+len(api.policies)+len(api.secrets) != 0 {
		t.Errorf("session objects survived teardown: pods=%d policies=%d secrets=%d", len(api.pods), len(api.policies), len(api.secrets))
	}
}

// TestGracefulStop_PassesTheDrainWindow pins that GracefulStop deletes the pod
// with the grace seconds as its GracePeriodSeconds, the SIGTERM-then-kill drain
// window — the ONLY difference from ForceKill.
func TestGracefulStop_PassesTheDrainWindow(t *testing.T) {
	p, api := seededProvider(t, runtime.TierGvisor, nil, nil)

	if err := p.Teardown().GracefulStop(context.Background(), sandboxHandle(), runtime.Duration(5)); err != nil {
		t.Fatalf("GracefulStop: %v", err)
	}
	assertOrder(t, api.calls, "DeletePod:ocu-sess-sess-abc:grace=5")
}

// TestForceKill_IdempotentOnAlreadyGone pins that a teardown of an
// already-torn-down session (every object not-found) is a SATISFIED kill, not an
// error: the finalizer maps not-found to done at every step.
func TestForceKill_IdempotentOnAlreadyGone(t *testing.T) {
	api := newFakeAPI() // empty: nothing seeded
	p, err := New(runtime.TierGvisor, Deps{API: api, RuntimeClass: "gvisor", Namespace: "ocu-sessions"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Teardown().ForceKill(context.Background(), sandboxHandle()); err != nil {
		t.Fatalf("ForceKill on an already-gone session must be satisfied, got %v", err)
	}
}

// TestFinalizer_NeverShortCircuits pins that a failing step does NOT abort the
// finalizer: even when the pod delete fails, the secret delete still runs, and
// the failure is surfaced as ErrTeardown. One failed step cannot strand a later
// resource.
func TestFinalizer_NeverShortCircuits(t *testing.T) {
	rev := &recordingRevoker{out: runtime.RevokeMarkedDead}
	p, api := seededProvider(t, runtime.TierGvisor, rev, nil)
	api.failOn["DeletePod"] = errors.New("apiserver hiccup")

	err := p.Teardown().ForceKill(context.Background(), sandboxHandle())
	if !errors.Is(err, runtime.ErrTeardown) {
		t.Fatalf("want ErrTeardown when a step fails, got %v", err)
	}
	// The secret delete (a LATER step) still ran despite the pod-delete failure.
	assertOrder(t, api.calls, "DeletePod:ocu-sess-sess-abc:grace=0", "DeleteSecret:ocu-sess-sess-abc")
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.secrets) != 0 {
		t.Error("secret survived — the finalizer short-circuited on the pod-delete failure")
	}
}

// TestReconcile_ReDerivesHandlesAndFlagsDeadPods pins the orphan sweep: it lists
// managed pods, re-derives a Sandbox from each pod's annotation, and marks a
// terminal pod !Alive so the lifecycle reclaims its slot and sweeps it.
func TestReconcile_ReDerivesHandlesAndFlagsDeadPods(t *testing.T) {
	api := newFakeAPI()
	p, err := New(runtime.TierGvisor, Deps{API: api, RuntimeClass: "gvisor", Namespace: "ocu-sessions"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A running managed pod and a failed managed pod.
	live := goodSpec()
	live.Name = "sess-live"
	_ = api.CreatePod(context.Background(), buildPod(live, "gvisor", "ocu-sessions"))
	api.markReady("ocu-sess-sess-live")

	dead := goodSpec()
	dead.Name = "sess-dead"
	deadPod := buildPod(dead, "gvisor", "ocu-sessions")
	_ = api.CreatePod(context.Background(), deadPod)
	api.mu.Lock()
	api.pods["ocu-sess-sess-dead"].Status.Phase = "Failed"
	api.mu.Unlock()

	sbs, err := p.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	byName := map[runtime.SessionName]runtime.Sandbox{}
	for _, s := range sbs {
		byName[s.Name] = s
	}
	if len(byName) != 2 {
		t.Fatalf("want 2 reconciled sandboxes, got %d", len(byName))
	}
	if !byName["sess-live"].Alive {
		t.Error("a running pod must reconcile as Alive (holds its slot)")
	}
	if byName["sess-dead"].Alive {
		t.Error("a Failed pod must reconcile as !Alive (substrate-lost, slot reclaimed)")
	}
	if byName["sess-live"].RuntimeID != "ocu-sess-sess-live" {
		t.Errorf("reconciled RuntimeID = %q, want the pure-function pod name", byName["sess-live"].RuntimeID)
	}
}
