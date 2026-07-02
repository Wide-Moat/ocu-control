// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// newAttestedScope builds a genuine OperatorScope for tests. Only the operator
// package can mint one via the seam; here we use the real NewOperatorSeam
// so the witness is genuine and scope.Valid() returns true.
func newAttestedScope(tenant, caller string) ingress.OperatorScope {
	seam := ingress.NewOperatorSeam()
	return seam.Mint(state.Identity{Tenant: tenant, Caller: caller})
}

// newFakeRerender returns a re-render callback that increments a counter on each
// call. Tests assert how many re-renders happened (0 on deny, 1 on success).
func newFakeRerender(counter *int) func(context.Context) (mcpkey.RenderOutcome, error) {
	return func(_ context.Context) (mcpkey.RenderOutcome, error) {
		*counter++
		return mcpkey.RenderOutcome{}, nil
	}
}

// newEngine is a convenience constructor for tests.
func newEngine(store mcpkey.RecordStore, sink audit.AuditSink, rerender func(context.Context) (mcpkey.RenderOutcome, error)) *mcpkey.Engine {
	minter := mcpkey.NewMinter()
	clk := state.NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	return mcpkey.NewEngine(minter, store, rerender, clk, sink)
}

// --- scope validity gate -------------------------------------------------------

// TestEngine_Create_ScopeInvalid confirms that calling Create with the zero-value
// (inert) OperatorScope returns ErrScopeInvalid BEFORE any mint, store write, or
// re-render. This is the runtime backstop to the compile-time seal.
func TestEngine_Create_ScopeInvalid(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	var zeroScope ingress.OperatorScope
	sk, rec, err := eng.Create(context.Background(), zeroScope, "tenant-1", "deploy-1", nil)
	if !errors.Is(err, mcpkey.ErrScopeInvalid) {
		t.Fatalf("Create(zero scope) err = %v, want ErrScopeInvalid", err)
	}
	if !sk.IsZero() {
		t.Error("Create(zero scope): returned non-zero SecretKey on scope refusal")
	}
	_ = rec
	if sink.Len() != 0 {
		t.Errorf("Create(zero scope): audit records emitted = %d, want 0", sink.Len())
	}
	if rerenderCount != 0 {
		t.Errorf("Create(zero scope): re-renders = %d, want 0", rerenderCount)
	}
}

// TestEngine_Revoke_ScopeInvalid confirms Revoke with the inert zero OperatorScope
// returns ErrScopeInvalid without any store write or re-render.
func TestEngine_Revoke_ScopeInvalid(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	var zeroScope ingress.OperatorScope
	_, err := eng.Revoke(context.Background(), zeroScope, "some-key-id", "test")
	if !errors.Is(err, mcpkey.ErrScopeInvalid) {
		t.Fatalf("Revoke(zero scope) err = %v, want ErrScopeInvalid", err)
	}
	if sink.Len() != 0 {
		t.Errorf("Revoke(zero scope): audit records emitted = %d, want 0", sink.Len())
	}
	if rerenderCount != 0 {
		t.Errorf("Revoke(zero scope): re-renders = %d, want 0", rerenderCount)
	}
}

// --- audit-before-ack fail-closed ------------------------------------------------

// TestEngine_Create_AuditFaultDenies proves that when the AuditSink is in fault
// mode, Create is denied: no SecretKey is returned, no Record is persisted to the
// store, and no artifact re-render fires. This is the SEC-45 fail-closed invariant:
// a key must not be live but un-recorded.
func TestEngine_Create_AuditFaultDenies(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	sink.SetFault(true, errors.New("disk full"))
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("tenant-A", "operator-1")
	sk, rec, err := eng.Create(context.Background(), scope, "tenant-A", "deploy-A", nil)
	if err == nil {
		t.Fatal("Create(audit-fault): expected non-nil error, got nil")
	}
	if !sk.IsZero() {
		t.Error("Create(audit-fault): returned non-zero SecretKey — key must not be minted on audit failure")
	}
	_ = rec

	// The store must be empty: no record persisted.
	recs, listErr := store.List(context.Background())
	if listErr != nil {
		t.Fatalf("List: %v", listErr)
	}
	if len(recs) != 0 {
		t.Errorf("Create(audit-fault): store has %d records, want 0 — record must not be persisted on audit failure", len(recs))
	}

	if rerenderCount != 0 {
		t.Errorf("Create(audit-fault): re-renders = %d, want 0 — artifact must not be re-rendered on audit failure", rerenderCount)
	}
}

// TestEngine_Revoke_AuditFaultDenies proves that when the AuditSink is in fault
// mode, Revoke is denied and the store record is NOT flipped to revoked.
func TestEngine_Revoke_AuditFaultDenies(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	// Seed a record to revoke.
	clk := state.NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	minter := mcpkey.NewMinter()
	sk, _ := minter.Mint()
	seedRec, _ := mcpkey.NewRecord(sk, "tenant-A", "deploy-A", time.Time{}, clk)
	_ = store.Put(context.Background(), seedRec)

	sink := audit.NewRecordingFake()
	sink.SetFault(true, errors.New("disk full"))
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("tenant-A", "operator-1")
	_, err := eng.Revoke(context.Background(), scope, seedRec.KeyID, "test-revoke")
	if err == nil {
		t.Fatal("Revoke(audit-fault): expected non-nil error, got nil")
	}

	// The record must still be active — not flipped to revoked.
	got, getErr := store.Get(context.Background(), seedRec.KeyID)
	if getErr != nil {
		t.Fatalf("Get: %v", getErr)
	}
	if got.Status != mcpkey.StatusActive {
		t.Errorf("Revoke(audit-fault): record status = %q, want %q — status must not flip on audit failure", got.Status, mcpkey.StatusActive)
	}

	if rerenderCount != 0 {
		t.Errorf("Revoke(audit-fault): re-renders = %d, want 0", rerenderCount)
	}
}

// --- happy path — Create --------------------------------------------------------

// TestEngine_Create_HappyPath confirms the full Create flow: mint, persist,
// re-render, and return the shown-once SecretKey. The audit Record must carry
// the key_id for correlation — NEVER the raw sk-ocu- key.
func TestEngine_Create_HappyPath(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("tenant-B", "operator-2")
	sk, rec, err := eng.Create(context.Background(), scope, "tenant-B", "deploy-B", nil)
	if err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
	if sk.IsZero() {
		t.Fatal("Create: returned zero SecretKey on success")
	}

	// The raw sk-ocu- key must have the correct prefix.
	raw := sk.Reveal()
	if len(raw) == 0 {
		t.Fatal("Create: Reveal() returned empty string")
	}
	if raw[:7] != "sk-ocu-" {
		t.Fatalf("Create: revealed key prefix = %q, want sk-ocu-", raw[:7])
	}

	// The record must be persisted in the store.
	stored, getErr := store.Get(context.Background(), rec.KeyID)
	if getErr != nil {
		t.Fatalf("Create: record not found in store: %v", getErr)
	}
	if stored.Status != mcpkey.StatusActive {
		t.Errorf("Create: stored record status = %q, want %q", stored.Status, mcpkey.StatusActive)
	}
	if stored.Tenant != "tenant-B" {
		t.Errorf("Create: stored record tenant = %q, want tenant-B", stored.Tenant)
	}

	// Re-render must have fired once.
	if rerenderCount != 1 {
		t.Errorf("Create: re-renders = %d, want 1", rerenderCount)
	}

	// Audit: exactly one record emitted, action = ActionMCPKeyCreate.
	auditRecs := sink.Records()
	if len(auditRecs) != 1 {
		t.Fatalf("Create: audit records emitted = %d, want 1", len(auditRecs))
	}
	ar := auditRecs[0]
	if ar.Action != audit.ActionMCPKeyCreate {
		t.Errorf("Create: audit action = %v, want ActionMCPKeyCreate", ar.Action)
	}
	// The audit record must carry the key_id for correlation, NEVER the raw key.
	if ar.Key != rec.KeyID {
		t.Errorf("Create: audit record Key = %q, want key_id = %q", ar.Key, rec.KeyID)
	}
	// Raw key must NOT appear in the audit record fields.
	rawKey := sk.Reveal()
	if ar.Key == rawKey {
		t.Error("Create: audit record Key is the raw sk-ocu- key — must be key_id only")
	}
	if ar.Reason == rawKey {
		t.Error("Create: audit record Reason contains the raw sk-ocu- key")
	}
	// Caller and Tenant come from the scope (host-attested), not the operator body.
	if ar.Caller != "operator-2" {
		t.Errorf("Create: audit Caller = %q, want operator-2 (host-attested)", ar.Caller)
	}
	if ar.Tenant != "tenant-B" {
		t.Errorf("Create: audit Tenant = %q, want tenant-B (host-attested scope identity)", ar.Tenant)
	}
}

// --- happy path — Revoke + re-render -------------------------------------------

// TestEngine_Revoke_HappyPath confirms the Revoke flow: the record status is
// flipped to revoked in the store, the artifact is re-rendered, and an audit
// record (ActionMCPKeyRevoke) is emitted BEFORE the status flip.
func TestEngine_Revoke_HappyPath(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	clk := state.NewFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	minter := mcpkey.NewMinter()
	sk, _ := minter.Mint()
	seedRec, _ := mcpkey.NewRecord(sk, "tenant-C", "deploy-C", time.Time{}, clk)
	_ = store.Put(context.Background(), seedRec)

	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("tenant-C", "operator-3")
	_, err := eng.Revoke(context.Background(), scope, seedRec.KeyID, "manual-revoke")
	if err != nil {
		t.Fatalf("Revoke: unexpected error: %v", err)
	}

	// Record must be flipped to revoked.
	got, getErr := store.Get(context.Background(), seedRec.KeyID)
	if getErr != nil {
		t.Fatalf("Get after revoke: %v", getErr)
	}
	if got.Status != mcpkey.StatusRevoked {
		t.Errorf("Revoke: record status = %q, want %q", got.Status, mcpkey.StatusRevoked)
	}

	// Re-render must have fired.
	if rerenderCount != 1 {
		t.Errorf("Revoke: re-renders = %d, want 1", rerenderCount)
	}

	// The revoked key must NOT appear in ActiveRecords.
	active, _ := store.ActiveRecords(context.Background(), clk.Now())
	for _, r := range active {
		if r.KeyID == seedRec.KeyID {
			t.Errorf("Revoke: revoked key %q still in ActiveRecords", seedRec.KeyID)
		}
	}

	// Audit: one record, action = ActionMCPKeyRevoke.
	auditRecs := sink.Records()
	if len(auditRecs) != 1 {
		t.Fatalf("Revoke: audit records = %d, want 1", len(auditRecs))
	}
	ar := auditRecs[0]
	if ar.Action != audit.ActionMCPKeyRevoke {
		t.Errorf("Revoke: audit action = %v, want ActionMCPKeyRevoke", ar.Action)
	}
	if ar.Key != seedRec.KeyID {
		t.Errorf("Revoke: audit record Key = %q, want key_id = %q", ar.Key, seedRec.KeyID)
	}
	if ar.Reason != "manual-revoke" {
		t.Errorf("Revoke: audit Reason = %q, want manual-revoke", ar.Reason)
	}
}

// --- rotation semantics --------------------------------------------------------

// TestEngine_Rotation_IsIssueNewPlusRevokeOld confirms that rotation is a fresh
// Create followed by a Revoke of the old key — there is no in-place secret
// mutation path. A Revoke never returns a new SecretKey; only Create does.
func TestEngine_Rotation_IsIssueNewPlusRevokeOld(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("tenant-D", "operator-4")
	// Issue the first key.
	sk1, rec1, err := eng.Create(context.Background(), scope, "tenant-D", "deploy-D", nil)
	if err != nil {
		t.Fatalf("Create first key: %v", err)
	}

	// Rotate: issue new, then revoke old.
	sk2, rec2, err := eng.Create(context.Background(), scope, "tenant-D", "deploy-D", nil)
	if err != nil {
		t.Fatalf("Create second key (rotation): %v", err)
	}
	if sk2.Reveal() == sk1.Reveal() {
		t.Error("Create produced identical secret on rotation — keys must be distinct")
	}
	if rec2.KeyID == rec1.KeyID {
		t.Error("Create produced identical key_id on rotation — key_ids must be distinct")
	}

	if _, err := eng.Revoke(context.Background(), scope, rec1.KeyID, "rotation"); err != nil {
		t.Fatalf("Revoke old key: %v", err)
	}

	// Old key is revoked; new key is active.
	old, _ := store.Get(context.Background(), rec1.KeyID)
	if old.Status != mcpkey.StatusRevoked {
		t.Errorf("old key status = %q, want revoked", old.Status)
	}
	newKey, _ := store.Get(context.Background(), rec2.KeyID)
	if newKey.Status != mcpkey.StatusActive {
		t.Errorf("new key status = %q, want active", newKey.Status)
	}
}

// --- tenant-is-input, caller-is-authority -------------------------------------

// TestEngine_TenantIsInput_CallerIsAuthority confirms that the created Record's
// Tenant comes from the operator-supplied tenant argument, while the audit actor
// comes from scope.Identity() (host-attested) — they are DISTINCT fields with
// distinct origins.
func TestEngine_TenantIsInput_CallerIsAuthority(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	// The OPERATOR's host-attested identity has tenant "ops-tenant" and caller "ops-user".
	// The TARGET tenant the new key is scoped to is "target-tenant" (legitimate operator input, Q3).
	scope := newAttestedScope("ops-tenant", "ops-user")
	_, rec, err := eng.Create(context.Background(), scope, "target-tenant", "deploy-E", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The record tenant is the operator-supplied target.
	if rec.Tenant != "target-tenant" {
		t.Errorf("Record.Tenant = %q, want target-tenant (operator-supplied target)", rec.Tenant)
	}

	// The audit record carries the ACTING identity from the scope, NOT the target tenant.
	auditRecs := sink.Records()
	if len(auditRecs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(auditRecs))
	}
	ar := auditRecs[0]
	if ar.Caller != "ops-user" {
		t.Errorf("audit Caller = %q, want ops-user (host-attested operator)", ar.Caller)
	}
	// The audit Tenant is from the scope identity (the operator's tenant), not the target.
	// NOTE: scope.Identity().Tenant is "ops-tenant".
	if ar.Tenant != "ops-tenant" {
		t.Errorf("audit Tenant = %q, want ops-tenant (operator's scope identity)", ar.Tenant)
	}
}
