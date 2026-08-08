// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	objmeta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestValidateSpec_EveryRefusalBranch exercises each fail-closed refusal so a
// mutation dropping any one guard reds here, not just the one the happy path
// happens to reach first.
func TestValidateSpec_EveryRefusalBranch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(s *runtime.SessionSpec)
	}{
		{"bad-schema", func(s *runtime.SessionSpec) { s.SchemaVersion = "v0-bogus" }},
		{"short-key", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyEd25519 = []byte{1, 2, 3} }},
		{"not-deny", func(s *runtime.SessionSpec) { s.Egress.DefaultDeny = false }},
		{"no-ci-guest-path", func(s *runtime.SessionSpec) { s.Handoff.ContainerInfoGuestPath = "" }},
		{"no-key-guest-path", func(s *runtime.SessionSpec) { s.Handoff.PublicKeyGuestPath = "" }},
		{"empty-image", func(s *runtime.SessionSpec) { s.Image = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := goodSpec()
			tc.mutate(&spec)
			if err := validateSpec(spec); !errors.Is(err, runtime.ErrUnsupportedSpec) {
				t.Fatalf("validateSpec(%s) = %v, want ErrUnsupportedSpec", tc.name, err)
			}
		})
	}
	if err := validateSpec(goodSpec()); err != nil {
		t.Fatalf("validateSpec(good) = %v, want nil", err)
	}
}

// TestWaitReady_SurfacesGetErrorAndDeadline covers waitReady's two non-happy
// exits: a GetPod error is surfaced, and a never-ready pod returns the context
// deadline rather than spinning forever.
func TestWaitReady_SurfacesGetErrorAndDeadline(t *testing.T) {
	// GetPod error surfaced.
	api := newFakeAPI()
	api.failOn["GetPod"] = errors.New("apiserver down")
	p := newTestProvider(t, api, runtime.TierGvisor)
	if err := p.waitReady(context.Background(), "ocu-sess-x"); err == nil {
		t.Error("waitReady did not surface the GetPod error")
	}

	// Never-ready pod: the context deadline fires.
	api2 := newFakeAPI()
	_ = api2.CreatePod(context.Background(), buildPod(goodSpec(), "gvisor", "ocu-sessions")) // stored, not ready
	p2 := newTestProvider(t, api2, runtime.TierGvisor)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := p2.waitReady(ctx, "ocu-sess-sess-abc"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waitReady on a never-ready pod = %v, want context deadline", err)
	}
}

// TestMaterialize_RollsBackOnWaitReadyFailure covers the last rollback arm: the
// pod was created but never becomes ready before the deadline, so Materialize
// unwinds all three objects and returns ErrMaterialize.
func TestMaterialize_RollsBackOnWaitReadyFailure(t *testing.T) {
	api := newFakeAPI() // readyOnCreate false: the pod never becomes ready
	p := newTestProvider(t, api, runtime.TierGvisor)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := p.Materialize(ctx, goodSpec())
	if !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("Materialize = %v, want ErrMaterialize on a never-ready pod", err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.pods)+len(api.policies)+len(api.secrets) != 0 {
		t.Errorf("objects survived the wait-ready rollback: pods=%d policies=%d secrets=%d", len(api.pods), len(api.policies), len(api.secrets))
	}
}

// TestReconcile_SkipsAPodWithNoSessionAnnotation covers the reconcile skip: a
// managed pod without the session-name annotation cannot be reclaimed by name,
// so it is skipped rather than given a fabricated identity.
func TestReconcile_SkipsAPodWithNoSessionAnnotation(t *testing.T) {
	api := newFakeAPI()
	// A managed pod carrying the label but NO session-name annotation.
	orphan := &corev1.Pod{ObjectMeta: objmeta.ObjectMeta{
		Name:      "ocu-sess-mangled",
		Namespace: "ocu-sessions",
		Labels:    map[string]string{labelManaged: managedLabelValue},
	}}
	_ = api.CreatePod(context.Background(), orphan)
	p := newTestProvider(t, api, runtime.TierGvisor)

	sbs, err := p.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(sbs) != 0 {
		t.Errorf("Reconcile returned %d sandboxes, want 0 (the unannotated pod is skipped)", len(sbs))
	}
}

// TestReconcile_SurfacesListError covers the list-error arm.
func TestReconcile_SurfacesListError(t *testing.T) {
	api := newFakeAPI()
	api.failOn["ListManagedPods"] = errors.New("list refused")
	p := newTestProvider(t, api, runtime.TierGvisor)
	if _, err := p.Reconcile(context.Background()); err == nil {
		t.Error("Reconcile did not surface the list error")
	}
}

// TestPureHelpers_DefaultBranches covers the fallback arms of the small pure
// helpers: a zero memory ceiling -> the 64 MiB tmpfs floor; a nil error stays
// nil through materializeError.
func TestPureHelpers_DefaultBranches(t *testing.T) {
	if got := tmpTmpfsBytes(0); got != 64<<20 {
		t.Errorf("tmpTmpfsBytes(0) = %d, want the 64 MiB floor", got)
	}
	if got := materializeError(nil); got != nil {
		t.Errorf("materializeError(nil) = %v, want nil", got)
	}
}

// TestNew_NilAPIBuildsTheRealAdapter covers New's nil-API branch: with no
// injected fake it tries the in-cluster adapter, which fails outside a cluster
// (no mounted service-account token). This exercises the real-adapter
// construction path and its error return without needing a cluster.
func TestNew_NilAPIBuildsTheRealAdapter(t *testing.T) {
	_, err := New(runtime.TierGvisor, Deps{Namespace: "ocu-sessions"})
	if err == nil {
		t.Skip("running inside a cluster: in-cluster config succeeded, nothing to assert")
	}
	// Outside a cluster the error names the in-cluster config failure.
	if err.Error() == "" {
		t.Error("New with a nil API returned an empty error")
	}
}
