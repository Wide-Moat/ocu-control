// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestNotImplemented_EveryMethod asserts EVERY method of the k8s provider and its
// teardown handle returns errors.Is(err, ErrNotImplemented) — the door is open,
// the room is empty. A future backend that wires a method must also flip this
// assertion, so the stub can never half-ship a method that silently no-ops.
func TestNotImplemented_EveryMethod(t *testing.T) {
	ctx := context.Background()
	p := New()

	// Provider satisfies the seam (also a compile-time assertion in k8s.go).
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
