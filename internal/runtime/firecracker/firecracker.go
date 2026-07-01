// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package firecracker is the Firecracker microVM RuntimeProvider: the door is
// open, the rooms are empty. Every method compiles and returns a typed
// runtime.ErrNotImplemented. Note the asymmetry the canon fixes: even on a
// Docker-provider deployment, a deployment bound to runtime.TierFirecracker
// aborts Materialize with ErrNotImplemented — there is no insecure fallback to a
// weaker tier, and the abort issues ZERO substrate calls. This package is the
// eventual home of the real microVM materialization; until then it imports only
// the seam.
package firecracker

import (
	"context"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// Provider is the Firecracker RuntimeProvider. It satisfies
// runtime.RuntimeProvider so the selector can return it behind the seam.
type Provider struct{}

// New builds the (empty) Firecracker provider. It does no I/O.
func New() *Provider { return &Provider{} }

var _ runtime.RuntimeProvider = (*Provider)(nil)

// Materialize is not implemented for the Firecracker backend yet.
func (*Provider) Materialize(context.Context, runtime.SessionSpec) (runtime.Sandbox, error) {
	return runtime.Sandbox{}, runtime.ErrNotImplemented
}

// Teardown returns the Firecracker finalizer handle. Its two verbs are
// NotImplemented until this backend lands.
func (*Provider) Teardown() runtime.RuntimeTeardown { return teardown{} }

// Reconcile is not implemented for the Firecracker backend yet.
func (*Provider) Reconcile(context.Context) ([]runtime.Sandbox, error) {
	return nil, runtime.ErrNotImplemented
}

// teardown is the Firecracker RuntimeTeardown handle. Both verbs are
// NotImplemented.
type teardown struct{}

var _ runtime.RuntimeTeardown = teardown{}

// GracefulStop is not implemented for the Firecracker backend yet.
func (teardown) GracefulStop(context.Context, runtime.Sandbox, runtime.Duration) error {
	return runtime.ErrNotImplemented
}

// ForceKill is not implemented for the Firecracker backend yet.
func (teardown) ForceKill(context.Context, runtime.Sandbox) error {
	return runtime.ErrNotImplemented
}
