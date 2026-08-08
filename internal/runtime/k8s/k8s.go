// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package k8s is the Kubernetes RuntimeProvider implementation. It materializes
// the substrate-neutral runtime.SessionSpec into one hardened per-session Pod
// plus a deny-all-egress NetworkPolicy and a projected handoff Secret — the k8s
// analog of the Docker impl's per-session Internal bridge + container. There is
// no per-session bridge to create (the coarse Materialize hides that
// difference); network isolation is a NetworkPolicy keyed on the session label.
// The deployment-wide runtime.RuntimeTier maps to a RuntimeClass.
//
// It honors every contract a second provider must: fail-closed pre-substrate
// validation, atomic Materialize with internal rollback (pod, then policy, then
// secret — reverse of create), pure-function naming so teardown and Reconcile
// re-derive every name without state, idempotency (not-found = satisfied), the
// kill-switch-first ordered finalizer, and the nil-collaborator shelf discipline.
package k8s

import (
	"context"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// Provider is the k8s RuntimeProvider. It holds the Kubernetes client behind the
// kubeAPI seam and the deployment-wide isolation tier + RuntimeClass it was
// constructed bound to (neither is per-request). It owns NO per-session state;
// teardown and Reconcile re-derive every resource name purely from the Sandbox's
// SessionName.
type Provider struct {
	api           kubeAPI
	tier          runtime.RuntimeTier
	runtimeClass  string
	namespace     string
	revoker       Revoker
	revokeAuditor RevokeAuditor
}

var _ runtime.RuntimeProvider = (*Provider)(nil)

// Deps are the below-seam collaborators, mirroring docker.Deps. A nil API makes
// New build the real in-cluster adapter; a test injects a recording fake. A nil
// Revoker / RevokeAuditor leaves the matching finalizer step an ordered no-op
// (the minimal shelf), exactly as the Docker impl does.
type Deps struct {
	API           kubeAPI
	Revoker       Revoker
	RevokeAuditor RevokeAuditor
	// RuntimeClass is the deployment's RuntimeClass name for the bound tier
	// (e.g. "gvisor"). Empty selects the cluster default (runc) — a dev-only
	// fallback, never a hardcoded class.
	RuntimeClass string
	// Namespace is the deployment-fixed namespace every session object lands in.
	Namespace string
}

// Revoker is the below-seam finalizer step-1 target (revoke session JWT), the
// same shape the Docker impl uses so the daemon wires ONE shared *cred.Revoker
// into whichever provider it built.
type Revoker interface {
	Revoke(ctx context.Context, bind runtime.EgressBinding) (runtime.RevokeOutcome, error)
}

// RevokeAuditor records the step-1 revoke outcome as destroy evidence. A nil
// auditor records nothing (the minimal shelf).
type RevokeAuditor interface {
	RecordRevokeOutcome(ctx context.Context, sess runtime.EgressBinding, outcome runtime.RevokeOutcome)
}

// New builds the k8s provider bound to the deployment-wide tier. When deps.API
// is nil it constructs the real in-cluster adapter; a test passes a fake through
// deps.API so no cluster is required. The tier and RuntimeClass are fixed at
// construction and can never be weakened by a request.
func New(tier runtime.RuntimeTier, deps Deps) (*Provider, error) {
	api := deps.API
	if api == nil {
		real, err := newInClusterAPI(deps.Namespace)
		if err != nil {
			return nil, err
		}
		api = real
	}
	return &Provider{
		api:           api,
		tier:          tier,
		runtimeClass:  deps.RuntimeClass,
		namespace:     deps.Namespace,
		revoker:       deps.Revoker,
		revokeAuditor: deps.RevokeAuditor,
	}, nil
}

// Materialize creates the per-session Secret, NetworkPolicy, and Pod atomically,
// then waits for the pod to become ready. It validates the spec and aborts the
// TierFirecracker tier with ZERO substrate calls (fail-closed, no weaker
// fallback). On any failure after the first create it rolls back the objects
// already created in REVERSE order (pod, policy, secret) so no orphan survives,
// and returns ErrMaterialize.
func (p *Provider) Materialize(ctx context.Context, spec runtime.SessionSpec) (runtime.Sandbox, error) {
	if err := validateSpec(spec); err != nil {
		return runtime.Sandbox{}, err
	}
	if p.tier == runtime.TierFirecracker {
		return runtime.Sandbox{}, fmt.Errorf("k8s: tier firecracker: %w", runtime.ErrNotImplemented)
	}

	secret := buildHandoffSecret(spec, p.namespace)
	policy := buildDenyAllEgressPolicy(spec, p.namespace)
	pod := buildPod(spec, p.runtimeClass, p.namespace)

	// A LIFO rollback stack: each successful create pushes its compensator, and a
	// later failure runs them in reverse so no orphan survives (the k8s analog of
	// the Docker container-then-network rollback).
	var rollback []func()
	unwind := func() {
		for i := len(rollback) - 1; i >= 0; i-- {
			rollback[i]()
		}
	}

	if err := p.api.CreateSecret(ctx, secret); err != nil && !isAlreadyExists(err) {
		return runtime.Sandbox{}, fmt.Errorf("k8s: create handoff secret: %w", materializeError(err))
	}
	rollback = append(rollback, func() { _ = p.api.DeleteSecret(context.WithoutCancel(ctx), secret.Name) })

	if err := p.api.CreateNetworkPolicy(ctx, policy); err != nil && !isAlreadyExists(err) {
		unwind()
		return runtime.Sandbox{}, fmt.Errorf("k8s: create egress policy: %w", materializeError(err))
	}
	rollback = append(rollback, func() { _ = p.api.DeleteNetworkPolicy(context.WithoutCancel(ctx), policy.Name) })

	if err := p.api.CreatePod(ctx, pod); err != nil && !isAlreadyExists(err) {
		unwind()
		return runtime.Sandbox{}, fmt.Errorf("k8s: create pod: %w", materializeError(err))
	}
	rollback = append(rollback, func() {
		_ = p.api.DeletePod(context.WithoutCancel(ctx), pod.Name, int64Ptr(0))
	})

	if err := p.waitReady(ctx, pod.Name); err != nil {
		unwind()
		return runtime.Sandbox{}, fmt.Errorf("k8s: wait ready: %w", materializeError(err))
	}

	return runtime.Sandbox{
		Name: spec.Name,
		// RuntimeID is the host-pre-derivable pod name, NOT the API-assigned pod
		// UID — the same discipline the Docker impl uses (deterministic name, not
		// the daemon's post-create id), so teardown needs no lookup.
		RuntimeID: pod.Name,
		Egress:    runtime.EgressBinding{Name: spec.Name, FilesystemID: spec.Egress.FilesystemID},
		Tier:      p.tier,
	}, nil
}

// Teardown returns the k8s finalizer handle bound to this provider.
func (p *Provider) Teardown() runtime.RuntimeTeardown {
	return &teardown{
		api:           p.api,
		revoker:       p.revoker,
		revokeAuditor: p.revokeAuditor,
	}
}

// Reconcile lists every managed pod and re-derives a Sandbox for each so the
// boot orphan sweep can reclaim sessions whose handle was lost across a restart.
// Alive is set from the pod phase: a Running pod holds its concurrency slot; a
// terminal (Succeeded/Failed) pod is substrate-lost, so the lifecycle reclaims
// the slot AND force-kills the dead pod.
func (p *Provider) Reconcile(ctx context.Context) ([]runtime.Sandbox, error) {
	pods, err := p.api.ListManagedPods(ctx)
	if err != nil {
		return nil, fmt.Errorf("k8s: list managed pods: %w", err)
	}
	out := make([]runtime.Sandbox, 0, len(pods))
	for i := range pods {
		pod := &pods[i]
		name := runtime.SessionName(pod.Annotations[annotationSessionName])
		if name == "" {
			// A managed pod with no session-name annotation cannot be reclaimed by
			// name; skip it rather than fabricate an identity. (Never happens for a
			// pod this provider created; a hand-mangled one is left for an operator.)
			continue
		}
		out = append(out, runtime.Sandbox{
			Name:      name,
			RuntimeID: pod.Name,
			Egress:    runtime.EgressBinding{Name: name, FilesystemID: labelToFilesystemID(pod)},
			Tier:      p.tier,
			Alive:     isPodAlive(pod),
		})
	}
	return out, nil
}

func int64Ptr(n int64) *int64 { return &n }
