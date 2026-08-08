// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// kubeAPI is the narrow substrate seam — the ONLY place a Kubernetes client is
// named, mirroring the Docker impl's dockerAPI discipline: the provider logic
// depends on exactly the verbs it uses, a test injects a recording fake, and the
// real adapter below is a thin projection over the typed clientset. Every method
// is namespace-implicit: the provider is constructed bound to ONE namespace
// (deployment-wide, never per-request), so no verb takes a namespace argument a
// request could vary.
type kubeAPI interface {
	// CreateSecret creates the per-session handoff Secret carrying the non-secret
	// container_info.json and the Ed25519 public key as data items. A conflict
	// (the secret already exists) is returned as-is for the caller to map.
	CreateSecret(ctx context.Context, s *corev1.Secret) error
	// CreateNetworkPolicy creates the per-session deny-all-egress NetworkPolicy.
	CreateNetworkPolicy(ctx context.Context, p *netv1.NetworkPolicy) error
	// CreatePod creates the per-session Pod. It is the last create in Materialize;
	// its failure triggers the rollback of the secret and policy already created.
	CreatePod(ctx context.Context, p *corev1.Pod) error
	// GetPod fetches a pod by name, for the readiness wait and Reconcile. A
	// not-found is surfaced (apierrors.IsNotFound) rather than swallowed.
	GetPod(ctx context.Context, name string) (*corev1.Pod, error)
	// DeletePod deletes a pod by name with the given grace period (seconds); a
	// nil grace uses the pod's terminationGracePeriodSeconds. Not-found is a
	// satisfied delete the caller maps to ErrNoSuchContainer.
	DeletePod(ctx context.Context, name string, graceSeconds *int64) error
	// DeleteNetworkPolicy / DeleteSecret remove the per-session side objects on
	// teardown. Not-found is a satisfied delete.
	DeleteNetworkPolicy(ctx context.Context, name string) error
	DeleteSecret(ctx context.Context, name string) error
	// ListManagedPods lists every pod carrying the managed label, for the boot
	// orphan sweep (Reconcile).
	ListManagedPods(ctx context.Context) ([]corev1.Pod, error)
}

// clientsetAPI is the real kubeAPI: a thin projection over the typed clientset,
// bound to one namespace. It is the only type that imports the Kubernetes SDK
// packages beyond the shared API types.
type clientsetAPI struct {
	cs        kubernetes.Interface
	namespace string
}

// newInClusterAPI builds the real adapter from the in-cluster service-account
// config (the pod's mounted token + the API server address from the
// environment). It is used when the daemon runs inside the cluster; a test
// never reaches it (it injects a fake kubeAPI).
func newInClusterAPI(namespace string) (*clientsetAPI, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s: in-cluster config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build clientset: %w", err)
	}
	return &clientsetAPI{cs: cs, namespace: namespace}, nil
}

func (a *clientsetAPI) CreateSecret(ctx context.Context, s *corev1.Secret) error {
	_, err := a.cs.CoreV1().Secrets(a.namespace).Create(ctx, s, metav1.CreateOptions{})
	return err
}

func (a *clientsetAPI) CreateNetworkPolicy(ctx context.Context, p *netv1.NetworkPolicy) error {
	_, err := a.cs.NetworkingV1().NetworkPolicies(a.namespace).Create(ctx, p, metav1.CreateOptions{})
	return err
}

func (a *clientsetAPI) CreatePod(ctx context.Context, p *corev1.Pod) error {
	_, err := a.cs.CoreV1().Pods(a.namespace).Create(ctx, p, metav1.CreateOptions{})
	return err
}

func (a *clientsetAPI) GetPod(ctx context.Context, name string) (*corev1.Pod, error) {
	return a.cs.CoreV1().Pods(a.namespace).Get(ctx, name, metav1.GetOptions{})
}

func (a *clientsetAPI) DeletePod(ctx context.Context, name string, graceSeconds *int64) error {
	return a.cs.CoreV1().Pods(a.namespace).Delete(ctx, name, metav1.DeleteOptions{GracePeriodSeconds: graceSeconds})
}

func (a *clientsetAPI) DeleteNetworkPolicy(ctx context.Context, name string) error {
	return a.cs.NetworkingV1().NetworkPolicies(a.namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (a *clientsetAPI) DeleteSecret(ctx context.Context, name string) error {
	return a.cs.CoreV1().Secrets(a.namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func (a *clientsetAPI) ListManagedPods(ctx context.Context) ([]corev1.Pod, error) {
	list, err := a.cs.CoreV1().Pods(a.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelManaged + "=" + managedLabelValue,
	})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// isNotFound reports whether err is a Kubernetes not-found, the substrate signal
// the provider maps to a satisfied delete / ErrNoSuchContainer.
func isNotFound(err error) bool { return apierrors.IsNotFound(err) }

// isAlreadyExists reports whether err is a Kubernetes already-exists conflict,
// used on the create path to make an idempotent re-create a satisfied no-op.
func isAlreadyExists(err error) bool { return apierrors.IsAlreadyExists(err) }
