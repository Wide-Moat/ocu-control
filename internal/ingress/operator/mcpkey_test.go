// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// newTestHandlersWithMCPKey extends newTestHandlers with an mcpkey.Engine
// collaborator wired into the Deps. The rerender callback is a no-op for these
// handler-layer tests (the Engine's own tests cover rerender behaviour).
func newTestHandlersWithMCPKey(t *testing.T, sink *audit.RecordingFake) (*operator.Handlers, *mcpkey.Engine) {
	t.Helper()
	clk := state.NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store := mcpkey.NewInMemRecordStore()
	minter := mcpkey.NewMinter()
	noopRerender := func(_ context.Context) (mcpkey.RenderOutcome, error) { return mcpkey.RenderOutcome{}, nil }
	eng := mcpkey.NewEngine(minter, store, noopRerender, clk, sink)

	h := operator.NewHandlers(operator.Deps{
		MCPKeyEngine: eng,
		Seam:         ingress.NewOperatorSeam(),
		Resolver:     operator.NewPeerCredResolver(nil),
	})
	return h, eng
}

// TestMCPKeyCreate_AttestedHappyPath confirms that MCPKeyCreate with an attested
// connection mints the OperatorScope from the held seam and drives Engine.Create,
// returning the shown-once SecretKey.
func TestMCPKeyCreate_AttestedHappyPath(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, _ := newTestHandlersWithMCPKey(t, sink)

	sk, rec, err := h.MCPKeyCreate(context.Background(), attestedConn(1001), "tenant-1", "deploy-1", nil)
	if err != nil {
		t.Fatalf("MCPKeyCreate: unexpected error: %v", err)
	}
	if sk.IsZero() {
		t.Fatal("MCPKeyCreate: returned zero SecretKey on success")
	}
	raw := sk.Reveal()
	if len(raw) < 7 || raw[:7] != "sk-ocu-" {
		t.Fatalf("MCPKeyCreate: revealed key prefix = %q, want sk-ocu-", raw[:7])
	}
	if rec.Tenant != "tenant-1" {
		t.Errorf("MCPKeyCreate: record Tenant = %q, want tenant-1", rec.Tenant)
	}
	if sink.Len() == 0 {
		t.Error("MCPKeyCreate: no audit record emitted")
	}
}

// TestMCPKeyCreate_UnattestedRefused confirms that MCPKeyCreate refuses an
// unattested connection with ingress.ErrUnattested BEFORE any engine call.
func TestMCPKeyCreate_UnattestedRefused(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, _ := newTestHandlersWithMCPKey(t, sink)

	sk, rec, err := h.MCPKeyCreate(context.Background(), unattestedConn(), "tenant-1", "deploy-1", nil)
	if !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("MCPKeyCreate(unattested): err = %v, want ErrUnattested", err)
	}
	if !sk.IsZero() {
		t.Error("MCPKeyCreate(unattested): non-zero SecretKey returned on refusal")
	}
	_ = rec
	if sink.Len() != 0 {
		t.Errorf("MCPKeyCreate(unattested): %d audit records emitted, want 0", sink.Len())
	}
}

// TestMCPKeyRevoke_AttestedHappyPath confirms that MCPKeyRevoke with an attested
// connection drives Engine.Revoke and returns nil on success.
func TestMCPKeyRevoke_AttestedHappyPath(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, eng := newTestHandlersWithMCPKey(t, sink)

	// First create a key to revoke.
	scope := ingress.NewOperatorSeam().Mint(state.Identity{Tenant: "tenant-2", Caller: "operator"})
	_, rec, err := eng.Create(context.Background(), scope, "tenant-2", "deploy-2", nil)
	if err != nil {
		t.Fatalf("Engine.Create: %v", err)
	}

	sink2 := audit.NewRecordingFake() // fresh sink for the handler call
	h2 := operator.NewHandlers(operator.Deps{
		MCPKeyEngine: eng,
		Seam:         ingress.NewOperatorSeam(),
		Resolver:     operator.NewPeerCredResolver(nil),
	})
	_ = mcpkey.NewInMemRecordStore() // silence unused import

	if _, err := h2.MCPKeyRevoke(context.Background(), attestedConn(1001), rec.KeyID, "test-revoke"); err != nil {
		t.Fatalf("MCPKeyRevoke: %v", err)
	}
	_ = sink2
	_ = h
}

// TestMCPKeyRevoke_UnattestedRefused confirms MCPKeyRevoke refuses an unattested
// connection with ingress.ErrUnattested before any engine call.
func TestMCPKeyRevoke_UnattestedRefused(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, _ := newTestHandlersWithMCPKey(t, sink)

	_, err := h.MCPKeyRevoke(context.Background(), unattestedConn(), "some-key-id", "reason")
	if !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("MCPKeyRevoke(unattested): err = %v, want ErrUnattested", err)
	}
}
