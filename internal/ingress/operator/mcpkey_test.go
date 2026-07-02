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
// collaborator wired into the Deps. It returns the backing RecordStore too so a
// test can re-read a record after a handler call and assert the durable state (a
// revoke actually flipped the status), not merely that the call returned nil. The
// rerender callback is a no-op for these handler-layer tests (the Engine's own
// tests cover rerender behaviour).
func newTestHandlersWithMCPKey(t *testing.T, sink *audit.RecordingFake) (*operator.Handlers, *mcpkey.Engine, mcpkey.RecordStore) {
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
	return h, eng, store
}

// TestMCPKeyCreate_AttestedHappyPath confirms that MCPKeyCreate with an attested
// connection mints the OperatorScope from the held seam and drives Engine.Create,
// returning the shown-once SecretKey.
func TestMCPKeyCreate_AttestedHappyPath(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, _, _ := newTestHandlersWithMCPKey(t, sink)

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
	h, _, _ := newTestHandlersWithMCPKey(t, sink)

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
// connection drives Engine.Revoke and DURABLY revokes the addressed key. It asserts
// the post-state in the store, not merely that the call returned nil: MCPKeyRevoke is
// idempotent (revoking an absent or wrong id also returns nil), so a nil return alone
// proves nothing — a handler that dropped the key id would still pass. Re-reading the
// record and asserting its status is StatusRevoked pins that the RIGHT key was flipped.
func TestMCPKeyRevoke_AttestedHappyPath(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, eng, store := newTestHandlersWithMCPKey(t, sink)

	// First create a key to revoke, through the same engine the handler drives.
	scope := ingress.NewOperatorSeam().Mint(state.Identity{Tenant: "tenant-2", Caller: "operator"})
	_, rec, err := eng.Create(context.Background(), scope, "tenant-2", "deploy-2", nil)
	if err != nil {
		t.Fatalf("Engine.Create: %v", err)
	}
	// Precondition: the freshly-created record is active in the store.
	before, err := store.Get(context.Background(), rec.KeyID)
	if err != nil {
		t.Fatalf("store.Get before revoke: %v", err)
	}
	if before.Status != mcpkey.StatusActive {
		t.Fatalf("precondition: created record status = %q, want active", before.Status)
	}

	if _, err := h.MCPKeyRevoke(context.Background(), attestedConn(1001), rec.KeyID, "test-revoke"); err != nil {
		t.Fatalf("MCPKeyRevoke: %v", err)
	}

	// The durable effect: the addressed record is now revoked in the store.
	after, err := store.Get(context.Background(), rec.KeyID)
	if err != nil {
		t.Fatalf("store.Get after revoke: %v", err)
	}
	if after.Status != mcpkey.StatusRevoked {
		t.Errorf("after MCPKeyRevoke, record %q status = %q, want revoked; the handler returned nil but did not durably revoke the addressed key", rec.KeyID, after.Status)
	}
	if sink.Len() == 0 {
		t.Error("MCPKeyRevoke: no audit record emitted for the successful revoke")
	}
}

// TestMCPKeyRevoke_UnattestedRefused confirms MCPKeyRevoke refuses an unattested
// connection with ingress.ErrUnattested before any engine call.
func TestMCPKeyRevoke_UnattestedRefused(t *testing.T) {
	t.Parallel()
	sink := audit.NewRecordingFake()
	h, _, _ := newTestHandlersWithMCPKey(t, sink)

	_, err := h.MCPKeyRevoke(context.Background(), unattestedConn(), "some-key-id", "reason")
	if !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("MCPKeyRevoke(unattested): err = %v, want ErrUnattested", err)
	}
}
