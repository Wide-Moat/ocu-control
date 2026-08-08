// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"crypto/ed25519"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

func goodSpec() runtime.SessionSpec {
	pub, _, _ := ed25519.GenerateKey(nil)
	return runtime.SessionSpec{
		SchemaVersion: runtime.SchemaV1Alpha,
		Name:          "sess-abc",
		Owner:         runtime.Identity{Tenant: "t-1", Caller: "caller-1"},
		Image:         "registry.internal/ocu-guest:pinned",
		Egress:        runtime.EgressPolicy{DefaultDeny: true, FilesystemID: "fs-9"},
		Resources:     runtime.ResourceCaps{CPUCores: 2, MemoryBytes: 512 << 20, PidsLimit: pidsPtr(256)},
		Handoff: runtime.HandoffMaterial{
			ContainerInfoJSON:      []byte("{}"),
			ContainerInfoHostPath:  "/host/ci.json",
			ContainerInfoGuestPath: "/container_info.json",
			PublicKeyEd25519:       pub,
			PublicKeyHostPath:      "/host/pub.key",
			PublicKeyGuestPath:     "/etc/ocu/auth_public_key",
			HostSockDir:            "/host/run/ocu",
		},
	}
}

func pidsPtr(n int64) *int64 { return &n }

// TestBuildPod_AppliesTheHost01Posture is the keystone: the pod-spec builder
// must stamp the full hardened posture on k8s primitives — the securityContext
// analog of the Docker HostConfig. Each assertion below binds one HOST-01
// property to the field that enforces it; a mutation dropping any single field
// reds exactly one assertion.
func TestBuildPod_AppliesTheHost01Posture(t *testing.T) {
	pod := buildPod(goodSpec(), "gvisor", "ocu-sessions")

	if pod.Name != "ocu-sess-sess-abc" {
		t.Errorf("pod name = %q, want the pure-function ocu-sess-<name>", pod.Name)
	}
	if pod.Namespace != "ocu-sessions" {
		t.Errorf("namespace = %q, want the deployment-fixed session namespace", pod.Namespace)
	}
	if pod.Spec.RuntimeClassName == nil || *pod.Spec.RuntimeClassName != "gvisor" {
		t.Errorf("runtimeClassName = %v, want the tier's gvisor class", pod.Spec.RuntimeClassName)
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Error("automountServiceAccountToken must be false: the guest cannot reach the API server (NFR-SEC-26)")
	}
	if pod.Spec.HostNetwork {
		t.Error("hostNetwork must be false: the guest's one leg is the egress trust-edge")
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restartPolicy = %q, want Never (one container per session, lifecycle bound to the session)", pod.Spec.RestartPolicy)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("want exactly one guest container, got %d", len(pod.Spec.Containers))
	}
	c := pod.Spec.Containers[0]
	if c.Image != "registry.internal/ocu-guest:pinned" {
		t.Errorf("image = %q, want the spec image verbatim", c.Image)
	}
	if len(c.Env) != 0 {
		t.Errorf("Env must be empty, got %d entries — the guest derives from the handoff, never process env", len(c.Env))
	}

	sc := c.SecurityContext
	if sc == nil {
		t.Fatal("guest container has no securityContext")
	}
	if sc.Privileged == nil || *sc.Privileged {
		t.Error("securityContext.privileged must be false")
	}
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
		t.Error("securityContext.allowPrivilegeEscalation must be false (no-new-privileges analog)")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("securityContext.readOnlyRootFilesystem must be true")
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("securityContext.runAsNonRoot must be true")
	}
	if sc.SeccompProfile == nil || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("securityContext.seccompProfile must be RuntimeDefault (no container without a profile)")
	}
	if sc.Capabilities == nil || len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("securityContext.capabilities.drop must be exactly [ALL], got %v", sc.Capabilities)
	}
}

// TestBuildPod_StampsHardResourceCeilings pins that the caps arrive as LIMITS,
// not requests-only weights: a hard CPU/memory ceiling, never a relative share.
func TestBuildPod_StampsHardResourceCeilings(t *testing.T) {
	pod := buildPod(goodSpec(), "gvisor", "ocu-sessions")
	limits := pod.Spec.Containers[0].Resources.Limits
	if limits == nil {
		t.Fatal("no resource limits stamped — caps must be hard ceilings")
	}
	mem := limits[corev1.ResourceMemory]
	if mem.Value() != 512<<20 {
		t.Errorf("memory limit = %d, want the 512Mi hard ceiling", mem.Value())
	}
	cpu := limits[corev1.ResourceCPU]
	if cpu.MilliValue() != 2000 {
		t.Errorf("cpu limit = %dm, want the 2-core hard ceiling", cpu.MilliValue())
	}
}

// TestBuildPod_NoRuntimeClassWhenUnset pins the dev-only runc fallback: an empty
// tier runtimeClass leaves the field unset (cluster default), never a hardcoded
// class — the same "unset = default" shape the Docker impl uses.
func TestBuildPod_NoRuntimeClassWhenUnset(t *testing.T) {
	pod := buildPod(goodSpec(), "", "ocu-sessions")
	if pod.Spec.RuntimeClassName != nil {
		t.Errorf("runtimeClassName = %v, want unset (cluster default) when no class is configured", *pod.Spec.RuntimeClassName)
	}
}

// TestBuildPod_MountsTheHandoffReadOnly pins that the non-secret handoff arrives
// as a read-only secret volume (k8s has no host binds), and the RW sock dir and
// /tmp scratch are writable emptyDirs on the read-only rootfs.
func TestBuildPod_MountsEachHandoffItemAtItsExactGuestPath(t *testing.T) {
	pod := buildPod(goodSpec(), "gvisor", "ocu-sessions")
	c := pod.Spec.Containers[0]

	// Each handoff item mounts read-only at its EXACT guest path via subPath —
	// container_info at the filesystem root (/container_info.json, the guest's
	// non-negotiable DEFAULT_PATH) and the key at /etc/ocu/auth_public_key. A
	// mount at a parent directory would either shadow the rootfs (for the root
	// path) or place the item where the guest never reads it — a silent
	// admission break (INTEGRATION.md invariant (i)).
	byPath := map[string]corev1.VolumeMount{}
	for _, m := range c.VolumeMounts {
		if m.Name == handoffVolumeName {
			byPath[m.MountPath] = m
		}
	}

	ci, ok := byPath["/container_info.json"]
	if !ok {
		t.Fatalf("no handoff mount at /container_info.json; mounts = %v", mountPaths(c.VolumeMounts, handoffVolumeName))
	}
	if ci.SubPath != handoffCIItem {
		t.Errorf("container_info subPath = %q, want %q", ci.SubPath, handoffCIItem)
	}
	if !ci.ReadOnly {
		t.Error("container_info mount must be read-only")
	}

	key, ok := byPath["/etc/ocu/auth_public_key"]
	if !ok {
		t.Fatalf("no handoff mount at /etc/ocu/auth_public_key; mounts = %v", mountPaths(c.VolumeMounts, handoffVolumeName))
	}
	if key.SubPath != handoffKeyItem {
		t.Errorf("public-key subPath = %q, want %q", key.SubPath, handoffKeyItem)
	}
	if !key.ReadOnly {
		t.Error("public-key mount must be read-only")
	}

	// Neither handoff mount lands at the filesystem root "/", which would shadow
	// the read-only rootfs (a broken pod, and the exact bug a parent-dir mount of
	// the root container_info path would cause).
	if _, bad := byPath["/"]; bad {
		t.Error("a handoff item is mounted at / — it would shadow the entire rootfs")
	}

	// The handoff volume is a per-session 0400 secret.
	var vol *corev1.Volume
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == handoffVolumeName {
			vol = &pod.Spec.Volumes[i]
		}
	}
	if vol == nil || vol.Secret == nil {
		t.Fatal("handoff volume is not a secret volume")
	}
	if vol.Secret.SecretName != "ocu-sess-sess-abc" {
		t.Errorf("handoff secret name = %q, want the per-session secret", vol.Secret.SecretName)
	}
}

func mountPaths(mounts []corev1.VolumeMount, name string) []string {
	var out []string
	for _, m := range mounts {
		if m.Name == name {
			out = append(out, m.MountPath+"[subPath="+m.SubPath+"]")
		}
	}
	return out
}
