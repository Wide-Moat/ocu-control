// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	objmeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	intstr "k8s.io/apimachinery/pkg/util/intstr"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// handoffCIItem / handoffKeyItem are the fixed data-item keys in the per-session
// handoff Secret; the guest reads them at the projected mount paths.
const (
	handoffCIItem  = "container_info.json"
	handoffKeyItem = "public_key.ed25519"
)

// validateSpec is the fail-closed pre-substrate gate, mirroring the Docker
// impl's: an unknown schema version, a wrong-length Ed25519 key, a non-deny
// egress posture, or a missing HOST-01 handoff path is refused with
// ErrUnsupportedSpec BEFORE any API call.
func validateSpec(spec runtime.SessionSpec) error {
	if spec.SchemaVersion != runtime.SchemaV1Alpha {
		return fmt.Errorf("k8s: schema version %q: %w", spec.SchemaVersion, runtime.ErrUnsupportedSpec)
	}
	if len(spec.Handoff.PublicKeyEd25519) != ed25519.PublicKeySize {
		return fmt.Errorf("k8s: ed25519 public key must be %d bytes, got %d: %w",
			ed25519.PublicKeySize, len(spec.Handoff.PublicKeyEd25519), runtime.ErrUnsupportedSpec)
	}
	if !spec.Egress.DefaultDeny {
		return fmt.Errorf("k8s: egress policy is not deny-default: %w", runtime.ErrUnsupportedSpec)
	}
	if spec.Handoff.ContainerInfoGuestPath == "" || spec.Handoff.PublicKeyGuestPath == "" {
		return fmt.Errorf("k8s: missing HOST-01 handoff guest path: %w", runtime.ErrUnsupportedSpec)
	}
	if spec.Image == "" {
		return fmt.Errorf("k8s: empty image: %w", runtime.ErrUnsupportedSpec)
	}
	return nil
}

// buildHandoffSecret projects the non-secret handoff material into a per-session
// Secret the pod mounts read-only. It is named by the pure-function pod name so
// teardown re-derives it without state.
func buildHandoffSecret(spec runtime.SessionSpec, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: objmeta.ObjectMeta{
			Name:        podName(spec.Name),
			Namespace:   namespace,
			Labels:      sessionLabels(spec),
			Annotations: map[string]string{annotationSessionName: string(spec.Name)},
		},
		Data: map[string][]byte{
			handoffCIItem:  spec.Handoff.ContainerInfoJSON,
			handoffKeyItem: spec.Handoff.PublicKeyEd25519,
		},
	}
}

// buildDenyAllEgressPolicy is the per-session network isolation object: a
// NetworkPolicy whose podSelector matches this session's pod and which denies
// ALL egress (an empty Egress rule set with the Egress policy type). It is the
// k8s analog of the Docker per-session Internal deny-all bridge. The one
// allow-listed upstream (the object store) is reached over the deployment's
// shared egress edge, not by punching this policy — the same posture as the
// Docker impl, where a storage session joins the shared egress network rather
// than getting outbound NAT on its own bridge.
func buildDenyAllEgressPolicy(spec runtime.SessionSpec, namespace string) *netv1.NetworkPolicy {
	return &netv1.NetworkPolicy{
		ObjectMeta: objmeta.ObjectMeta{
			Name:        policyName(spec.Name),
			Namespace:   namespace,
			Labels:      sessionLabels(spec),
			Annotations: map[string]string{annotationSessionName: string(spec.Name)},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: objmeta.LabelSelector{
				MatchLabels: map[string]string{labelSessionName: nameHash(string(spec.Name))},
			},
			// Deny-all egress: declaring the Egress policy type with NO egress rule
			// means every outbound connection is denied. Ingress is unrestricted by
			// this object (the control/exec plane reaches the guest); a separate
			// cluster policy governs ingress if the deployment needs it.
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress:      []netv1.NetworkPolicyEgressRule{},
		},
	}
}

// materializeError maps a substrate error to the seam's typed sentinels. A
// not-found on the wait path (the pod vanished mid-create) is still an
// ErrMaterialize — the create did not complete — so the caller unwinds.
func materializeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", runtime.ErrMaterialize, err)
}

// waitReady polls the pod until it reports Ready with a non-empty pod IP, or the
// context deadline fires. Readiness requires BOTH the PodReady condition AND an
// assigned IP: PodReady alone races IP assignment, and the exec plane needs the
// IP to dial the guest. It is the k8s analog of the Docker wait-for-running.
func (p *Provider) waitReady(ctx context.Context, name string) error {
	const poll = 200 * time.Millisecond
	for {
		pod, err := p.api.GetPod(ctx, name)
		if err != nil {
			return err
		}
		if isPodReady(pod) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// isPodReady reports whether a pod has the PodReady condition true AND a
// non-empty pod IP.
func isPodReady(pod *corev1.Pod) bool {
	if pod.Status.PodIP == "" {
		return false
	}
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// isPodAlive reports whether a pod is in a non-terminal phase (Pending or
// Running). A Succeeded/Failed pod is substrate-lost: the reconciler reclaims its
// concurrency slot and force-kills it.
func isPodAlive(pod *corev1.Pod) bool {
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return false
	default:
		return true
	}
}

// labelToFilesystemID is a best-effort recovery of the egress scope for the
// reconcile handle. The real filesystem_id is not stored on the pod (only its
// hash label is), and the teardown revoke keys on the host-derived session Name
// anyway (Sandbox.Egress.Name), NOT FilesystemID — so an empty value here is
// harmless. It exists so the field is explicit rather than silently zero.
func labelToFilesystemID(_ *corev1.Pod) string { return "" }

// egressToPort is retained for a future allow-list policy that names the object
// store port; the v1 deny-all policy uses no port. Kept unexported and unused-safe.
var _ = intstr.FromInt
