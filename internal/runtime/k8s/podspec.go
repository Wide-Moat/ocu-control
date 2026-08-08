// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/api/resource"
	objmeta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// guestContainerName is the fixed name of the single sandbox container in a
// session pod. It is not derived from the session (the pod is already
// per-session); a stable name lets the exec/log path address the container.
const guestContainerName = "guest"

// handoffVolumeName / handoffMountPath project the non-secret handoff material
// (container_info.json, the Ed25519 public key) into the guest. Under Docker
// these are :ro host binds; k8s has no host binds, so they arrive as a
// projected read-only volume the provider populates from a per-session Secret.
const (
	handoffVolumeName = "ocu-handoff"
	sockVolumeName    = "ocu-sock"
	sockMountPath     = "/run/ocu"
	tmpVolumeName     = "ocu-tmp"
	tmpMountPath      = "/tmp"
)

// buildPod is the pure function from the substrate-neutral SessionSpec to a
// hardened per-session Pod. It applies the HOST-01 posture on k8s primitives —
// the securityContext analog of the Docker HostConfig: drop ALL capabilities,
// no privilege escalation, a read-only root filesystem, run as a non-root user,
// the seccomp RuntimeDefault profile, no mounted service-account token, and the
// hard CPU/memory/pids caps as resource LIMITS (ceilings, never requests-only
// weights). The kernel-isolation tier is the runtimeClassName, the ONLY
// tier-dependent field. It creates no object; the caller applies it.
//
// runtimeClass is the deployment's RuntimeClass for the bound tier (e.g.
// "gvisor"); empty means the cluster default (runc) — a dev-only fallback, the
// same "unset = daemon default" shape the Docker impl uses for its runtime
// string. namespace is the deployment-fixed session namespace.
func buildPod(spec runtime.SessionSpec, runtimeClass, namespace string) *corev1.Pod {
	falseP := boolPtr(false)
	trueP := boolPtr(true)

	sc := &corev1.SecurityContext{
		Privileged:               falseP,
		AllowPrivilegeEscalation: falseP,
		ReadOnlyRootFilesystem:   trueP,
		RunAsNonRoot:             trueP,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}

	limits := corev1.ResourceList{
		corev1.ResourceMemory: *metav1.NewQuantity(spec.Resources.MemoryBytes, metav1.BinarySI),
		corev1.ResourceCPU:    *metav1.NewMilliQuantity(int64(spec.Resources.CPUCores*1000), metav1.DecimalSI),
	}

	vols := []corev1.Volume{
		// The RW sock dir the guest creates its exec UDS in (Docker's HostSockDir
		// bind). An emptyDir gives the guest a writable path on the read-only
		// rootfs; it dies with the pod.
		{Name: sockVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		// /tmp scratch on the read-only rootfs, size-capped RAM counted against
		// the memory ceiling (Medium = tmpfs), mirroring the Docker /tmp tmpfs.
		{Name: tmpVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
			Medium:    corev1.StorageMediumMemory,
			SizeLimit: quantityPtr(tmpTmpfsBytes(spec.Resources.MemoryBytes)),
		}}},
		// The non-secret handoff material as a read-only projected secret volume.
		{Name: handoffVolumeName, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  podName(spec.Name),
			DefaultMode: int32Ptr(0o400),
		}}},
	}

	mounts := []corev1.VolumeMount{
		{Name: sockVolumeName, MountPath: sockMountPath},
		{Name: tmpVolumeName, MountPath: tmpMountPath},
		{Name: handoffVolumeName, MountPath: handoffMountDir(spec), ReadOnly: true},
	}

	pod := &corev1.Pod{
		ObjectMeta: objmeta.ObjectMeta{
			Name:        podName(spec.Name),
			Namespace:   namespace,
			Labels:      sessionLabels(spec),
			Annotations: map[string]string{annotationSessionName: string(spec.Name)},
		},
		Spec: corev1.PodSpec{
			// No service-account token in the guest: it must not be able to reach
			// the API server (NFR-SEC-26 — the guest surface cannot manage the
			// platform).
			AutomountServiceAccountToken: falseP,
			// The guest never joins the host network; its one outbound leg is the
			// egress trust-edge, enforced by the per-session NetworkPolicy.
			HostNetwork:   false,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:            guestContainerName,
				Image:           spec.Image,
				SecurityContext: sc,
				Resources:       corev1.ResourceRequirements{Limits: limits, Requests: limits},
				VolumeMounts:    mounts,
				// Empty Env: the guest derives everything from the mounted handoff,
				// never from a process env the pod spec could leak (Docker: empty Env).
				Env: nil,
			}},
			Volumes: vols,
		},
	}
	if runtimeClass != "" {
		pod.Spec.RuntimeClassName = &runtimeClass
	}
	return pod
}

// handoffMountDir is the parent directory the read-only handoff secret mounts
// at. The guest reads container_info.json and the public key from fixed paths
// under it; the provider derives the directory from the guest paths the spec
// carries so the mount target never drifts from what the guest reads.
func handoffMountDir(spec runtime.SessionSpec) string {
	if spec.Handoff.ContainerInfoGuestPath != "" {
		return parentDir(spec.Handoff.ContainerInfoGuestPath)
	}
	return "/etc/ocu"
}

// tmpTmpfsBytes bounds the /tmp tmpfs to a fraction of the memory ceiling so a
// runaway /tmp cannot itself exhaust the whole cgroup ceiling before the OOM
// killer fires on the workload. It mirrors the Docker impl's bounded /tmp.
func tmpTmpfsBytes(memBytes int64) int64 {
	const denom = 4
	if memBytes <= 0 {
		return 64 << 20 // 64 MiB floor when no ceiling is set (test path)
	}
	return memBytes / denom
}
