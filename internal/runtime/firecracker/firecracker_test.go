// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package firecracker

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestNotImplemented_EveryMethod asserts EVERY method of the Firecracker provider
// and its teardown handle returns errors.Is(err, ErrNotImplemented). This is the
// in-package complement of the Docker provider's TierFirecracker abort: even when
// a Docker deployment is bound to TierFirecracker the create aborts with the same
// sentinel — there is no insecure fallback to a weaker tier from any direction.
func TestNotImplemented_EveryMethod(t *testing.T) {
	ctx := context.Background()
	p := New()

	// Provider satisfies the seam (also a compile-time assertion in firecracker.go).
	var _ runtime.RuntimeProvider = p

	if _, err := p.Materialize(ctx, runtime.SessionSpec{}); !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("Materialize: want ErrNotImplemented, got %v", err)
	}
	if _, err := p.Reconcile(ctx); !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("Reconcile: want ErrNotImplemented, got %v", err)
	}

	td := p.Teardown()
	if td == nil {
		t.Fatalf("Teardown returned a nil handle")
	}
	if err := td.GracefulStop(ctx, runtime.Sandbox{}, runtime.Duration(0)); !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("GracefulStop: want ErrNotImplemented, got %v", err)
	}
	if err := td.ForceKill(ctx, runtime.Sandbox{}); !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("ForceKill: want ErrNotImplemented, got %v", err)
	}
}
