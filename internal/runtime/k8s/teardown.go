// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// stepTimeout bounds each finalizer step, derived from a detached base so a
// cancelled parent context cannot strand a half-freed session and one hung step
// cannot block a later one. It mirrors the Docker impl's per-step timeout.
const stepTimeout = 30 * time.Second

// teardown is the k8s RuntimeTeardown handle. Its two verbs run the same ordered
// host-driven finalizer; they differ only in the drain window before the pod
// delete. It holds the below-seam Revoker/RevokeAuditor and the kubeAPI, never
// per-session state — every name is re-derived from the Sandbox's SessionName.
type teardown struct {
	api           kubeAPI
	revoker       Revoker
	revokeAuditor RevokeAuditor
}

var _ runtime.RuntimeTeardown = (*teardown)(nil)

// GracefulStop runs the finalizer with a SIGTERM-then-kill drain window of grace
// whole seconds before the pod delete: the pod delete uses grace as its
// GracePeriodSeconds, giving the guest grace to flush before the kubelet kills
// it. Every other finalizer step runs host-side (control-plane-side) regardless
// of whether the guest honored the drain.
func (t *teardown) GracefulStop(ctx context.Context, sess runtime.Sandbox, grace runtime.Duration) error {
	g := int64(grace)
	return t.finalize(ctx, sess, &g)
}

// ForceKill runs the finalizer with NO drain window: the pod delete uses grace 0
// (immediate). Idempotent — a not-found pod is a satisfied kill.
func (t *teardown) ForceKill(ctx context.Context, sess runtime.Sandbox) error {
	return t.finalize(ctx, sess, int64Ptr(0))
}

// finalize runs the EXACT NFR-SEC-65 step order, none depending on guest
// cooperation, under a detached context with a per-step bounded timeout. It
// NEVER short-circuits: every step runs even if an earlier one failed, and the
// failures are joined into one ErrTeardown so one failed step cannot strand a
// later resource.
//
// The k8s step order maps onto the canon order:
//  1. revoke session JWT (the kill-switch-first step)
//  2. drop egress route host-side — delete the per-session NetworkPolicy, which
//     removes the session's outbound allowance even if the guest is unresponsive
//     (NFR-SEC-27)
//  3. (tmpfs/scratch zero) — the pod's emptyDir/tmpfs volumes die with the pod;
//     there is no host-side scratch to scrub, so this canon step is an ordered
//     no-op under k8s, recorded here to keep the order explicit
//  4. (unmount data scope) — the mount lives inside the pod; deleting the pod
//     unmounts it. Ordered no-op.
//  5. kill the process tree — delete the pod (grace 0 on ForceKill), which the
//     kubelet enforces by killing the container. A not-found is a satisfied kill.
//  6. destroy side objects — delete the handoff Secret. (No cgroup/network to
//     destroy separately: the pod delete cascades the container; the policy went
//     in step 2.)
func (t *teardown) finalize(parent context.Context, sess runtime.Sandbox, graceSeconds *int64) error {
	base := context.WithoutCancel(parent)
	var errs []error

	step := func(name string, fn func(ctx context.Context) error) {
		ctx, cancel := context.WithTimeout(base, stepTimeout)
		defer cancel()
		if err := fn(ctx); err != nil {
			errs = append(errs, fmt.Errorf("k8s teardown %s: %w", name, err))
		}
	}

	// Step 1: revoke the session JWT (kill-switch-first). A nil Revoker leaves it
	// an ordered no-op (the minimal shelf).
	step("revoke-jwt", func(ctx context.Context) error {
		if t.revoker == nil {
			return nil
		}
		outcome, err := t.revoker.Revoke(ctx, sess.Egress)
		if err != nil {
			return err
		}
		if t.revokeAuditor != nil {
			t.revokeAuditor.RecordRevokeOutcome(ctx, sess.Egress, outcome)
		}
		return nil
	})

	// Step 2: drop the egress route host-side — delete the per-session policy even
	// if the guest is unresponsive (NFR-SEC-27). Not-found is satisfied.
	step("drop-egress", func(ctx context.Context) error {
		if err := t.api.DeleteNetworkPolicy(ctx, policyName(sess.Name)); err != nil && !isNotFound(err) {
			return err
		}
		return nil
	})

	// Step 5: kill the process tree — delete the pod. Not-found = satisfied kill.
	step("kill-pod", func(ctx context.Context) error {
		if err := t.api.DeletePod(ctx, podName(sess.Name), graceSeconds); err != nil && !isNotFound(err) {
			return err
		}
		return nil
	})

	// Step 6: destroy side objects — delete the handoff Secret. Not-found = done.
	step("delete-secret", func(ctx context.Context) error {
		if err := t.api.DeleteSecret(ctx, podName(sess.Name)); err != nil && !isNotFound(err) {
			return err
		}
		return nil
	})

	if len(errs) > 0 {
		return fmt.Errorf("%w: %v", runtime.ErrTeardown, errors.Join(errs...))
	}
	return nil
}
