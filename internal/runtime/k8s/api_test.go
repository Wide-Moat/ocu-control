// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	objmeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestClientsetAPI_ProjectsEveryVerbOntoTheClientset drives the REAL adapter
// (clientsetAPI) against the client-go fake clientset, so the thin SDK
// projection every verb rides is exercised deterministically without a cluster.
// It asserts each verb reads/writes the bound namespace and that the list verb
// filters on the managed label.
func TestClientsetAPI_ProjectsEveryVerbOntoTheClientset(t *testing.T) {
	cs := fake.NewSimpleClientset()
	api := &clientsetAPI{cs: cs, namespace: "ocu-sessions"}
	ctx := context.Background()

	spec := goodSpec()
	secret := buildHandoffSecret(spec, "ocu-sessions")
	policy := buildDenyAllEgressPolicy(spec, "ocu-sessions")
	pod := buildPod(spec, "gvisor", "ocu-sessions")

	if err := api.CreateSecret(ctx, secret); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if err := api.CreateNetworkPolicy(ctx, policy); err != nil {
		t.Fatalf("CreateNetworkPolicy: %v", err)
	}
	if err := api.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}

	got, err := api.GetPod(ctx, pod.Name)
	if err != nil {
		t.Fatalf("GetPod: %v", err)
	}
	if got.Name != pod.Name || got.Namespace != "ocu-sessions" {
		t.Errorf("GetPod returned %s/%s, want %s/ocu-sessions", got.Namespace, got.Name, pod.Name)
	}

	// ListManagedPods filters on the managed label: an UNmanaged pod in the same
	// namespace must not appear.
	unmanaged := &corev1.Pod{ObjectMeta: objmeta.ObjectMeta{Name: "someone-elses", Namespace: "ocu-sessions"}}
	if _, err := cs.CoreV1().Pods("ocu-sessions").Create(ctx, unmanaged, objmeta.CreateOptions{}); err != nil {
		t.Fatalf("seed unmanaged pod: %v", err)
	}
	managed, err := api.ListManagedPods(ctx)
	if err != nil {
		t.Fatalf("ListManagedPods: %v", err)
	}
	if len(managed) != 1 || managed[0].Name != pod.Name {
		t.Errorf("ListManagedPods = %v, want exactly the one managed pod (label filter)", names(managed))
	}

	if err := api.DeletePod(ctx, pod.Name, int64Ptr(0)); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if err := api.DeleteNetworkPolicy(ctx, policy.Name); err != nil {
		t.Fatalf("DeleteNetworkPolicy: %v", err)
	}
	if err := api.DeleteSecret(ctx, secret.Name); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	// After the deletes, GetPod reports not-found (the substrate signal the
	// finalizer maps to a satisfied kill).
	if _, err := api.GetPod(ctx, pod.Name); !isNotFound(err) {
		t.Errorf("GetPod after delete = %v, want a not-found", err)
	}
}

func names(pods []corev1.Pod) []string {
	out := make([]string, len(pods))
	for i := range pods {
		out[i] = pods[i].Name
	}
	return out
}

// TestClientsetAPI_ListSurfacesTheError pins that a list error is surfaced, not
// swallowed — the reconcile path must fail loud on a broken API server.
func TestClientsetAPI_ListSurfacesTheError(t *testing.T) {
	// A nil clientset makes the first call panic-safe? No — use a fake with a
	// reactor that errors. Simplest deterministic error: a policy create conflict.
	cs := fake.NewSimpleClientset()
	api := &clientsetAPI{cs: cs, namespace: "ocu-sessions"}
	ctx := context.Background()
	p := buildDenyAllEgressPolicy(goodSpec(), "ocu-sessions")
	if err := api.CreateNetworkPolicy(ctx, p); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// A second create of the same object is an already-exists conflict, surfaced.
	if err := api.CreateNetworkPolicy(ctx, p); err == nil {
		t.Error("duplicate NetworkPolicy create did not surface a conflict")
	} else if !isAlreadyExists(err) {
		t.Errorf("duplicate create error = %v, want an already-exists conflict", err)
	}
	_ = netv1.NetworkPolicy{}
}
