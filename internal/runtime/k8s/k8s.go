// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package k8s is the Kubernetes RuntimeProvider implementation: the door is open,
// the rooms are empty. Every method compiles and returns a typed
// runtime.ErrNotImplemented, so a future backend lands inside this package without
// touching any caller. It imports no Kubernetes client; it imports only the seam.
//
// When this backend is built it materializes the substrate-neutral
// runtime.SessionSpec into a Pod plus a deny-all NetworkPolicy (there is no
// per-session bridge to create — the coarse Materialize hides that difference),
// maps the deployment-wide runtime.RuntimeTier to a RuntimeClass, and projects
// each runtime.MountIntent into a volume + secret. Until then it is NotImplemented.
package k8s

import (
	"context"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// Provider is the k8s RuntimeProvider. It satisfies runtime.RuntimeProvider so
// the selector can return it behind the seam.
type Provider struct{}

// New builds the (empty) k8s provider. It does no I/O.
func New() *Provider { return &Provider{} }

var _ runtime.RuntimeProvider = (*Provider)(nil)

// Materialize is not implemented for the k8s backend yet.
func (*Provider) Materialize(context.Context, runtime.SessionSpec) (runtime.Sandbox, error) {
	return runtime.Sandbox{}, runtime.ErrNotImplemented
}

// Teardown returns the k8s finalizer handle. Its two verbs are NotImplemented
// until this backend lands.
func (*Provider) Teardown() runtime.RuntimeTeardown { return teardown{} }

// Reconcile is not implemented for the k8s backend yet.
func (*Provider) Reconcile(context.Context) ([]runtime.Sandbox, error) {
	return nil, runtime.ErrNotImplemented
}

// teardown is the k8s RuntimeTeardown handle. Both verbs are NotImplemented.
type teardown struct{}

var _ runtime.RuntimeTeardown = teardown{}

// GracefulStop is not implemented for the k8s backend yet.
func (teardown) GracefulStop(context.Context, runtime.Sandbox, runtime.Duration) error {
	return runtime.ErrNotImplemented
}

// ForceKill is not implemented for the k8s backend yet.
func (teardown) ForceKill(context.Context, runtime.Sandbox) error {
	return runtime.ErrNotImplemented
}
