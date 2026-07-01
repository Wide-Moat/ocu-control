// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrScopeInvalid is the fail-closed refusal when an Engine method is called with
// an OperatorScope that is not a genuine minted scope (the inert zero value, or one
// minted from a forged zero-value seam). The compile-time seal makes a gateway call
// impossible to form; this is the runtime backstop against a zero-value scope passed
// by reflection or an accidental struct copy. Callers match it with errors.Is.
var ErrScopeInvalid = errors.New("mcpkey: operator scope invalid, action refused (fail-closed)")

// ErrTenantMissing and ErrDeploymentMissing refuse a mint whose tenant or
// deployment is empty, before any side effect. The published A2 record pins
// both fields with minLength 1 (contracts/mcp/mcp-key-set.schema.json) and the
// canon create-request marks both required, so admitting either empty would
// mint a record the hashed-key-set artifact cannot legally render.
var (
	ErrTenantMissing     = errors.New("mcpkey: tenant is required (fail-closed)")
	ErrDeploymentMissing = errors.New("mcpkey: deployment is required (fail-closed)")
)

// Engine is the composition core for the MCP API key operator verbs. It owns
// Create (mint → persist → re-render) and Revoke (flip status → re-render), both
// AUDIT-FIRST and fail-closed: the audit Record is emitted BEFORE any durable
// mutation is acknowledged externally, and a non-nil Emit result DENIES the action
// — nothing is persisted or published, and no SecretKey is returned on a Create
// fault. Both methods require a genuine ingress.OperatorScope, so a gateway caller
// — which holds no seam — cannot compile a call (NFR-SEC-52 as a compile fact,
// mirroring killswitch.Engine).
//
// The re-render callback is a plain func(ctx) error so the Engine does not import
// any cmd-level wiring. The daemon supplies the concrete WriteKeySet-over-the-live-
// set closure in plan 08-05; tests inject a simple counting stub.
type Engine struct {
	minter   *Minter
	store    RecordStore
	rerender func(context.Context) error
	clk      state.Clock
	audit    audit.AuditSink
}

// NewEngine constructs an Engine from its collaborators. The rerender callback is
// called AFTER every successful Create/Revoke; it re-renders the artifact from the
// current live set. The same Clock the store was built with must be passed so the
// whole write path reads time through one seam.
func NewEngine(minter *Minter, store RecordStore, rerender func(context.Context) error, clk state.Clock, sink audit.AuditSink) *Engine {
	return &Engine{
		minter:   minter,
		store:    store,
		rerender: rerender,
		clk:      clk,
		audit:    sink,
	}
}

// Create mints a new sk-ocu- MCP API key, records it, re-renders the artifact, and
// returns the shown-once SecretKey + the persisted Record. It is AUDIT-FIRST and
// fail-closed: the audit Record (ActionMCPKeyCreate, carrying key_id — NEVER the
// raw key) is emitted BEFORE any durable mutation is acknowledged externally. A
// non-nil Emit result DENIES the action: no SecretKey is returned, nothing is
// persisted, and no artifact is re-rendered.
//
// Ordering: (1) mint sk + build Record (produces key_id for audit correlation);
// (2) Emit audit Record with key_id — DENY on failure (return nothing); (3) Put
// record to store; (4) re-render artifact; (5) return SecretKey to caller.
// Step (3–5) happen ONLY after a successful (2). This places the audit event
// durably before any external acknowledgement, satisfying the fail-closed invariant
// (NFR-SEC-45) while still carrying the key_id in the audit trail.
//
// The scope parameter is the operator capability (NFR-SEC-52): a gateway caller
// cannot obtain one, so this method is unreachable from any gateway route. The
// scope.Valid() check is the runtime backstop to the compile-time seal, mirroring
// killswitch.Engine.RevokeOne exactly.
//
// tenant is the operator-supplied target tenant the new key is scoped to — a
// legitimate operator input (Q3 of the research). The audit actor is always
// scope.Identity() (the host-attested operator from peer-creds), never the tenant
// body field (NFR-SEC-43). expiresAt is optional: nil means non-expiring (ADR-0027).
func (e *Engine) Create(ctx context.Context, scope ingress.OperatorScope, tenant, deployment string, expiresAt *time.Time) (SecretKey, Record, error) {
	if !scope.Valid() {
		return SecretKey{}, Record{}, ErrScopeInvalid
	}
	if tenant == "" {
		return SecretKey{}, Record{}, ErrTenantMissing
	}
	if deployment == "" {
		return SecretKey{}, Record{}, ErrDeploymentMissing
	}

	// Step 1: Mint the sk and build the full Record, which produces the key_id we
	// need for the audit correlation field. The raw key never escapes: it is consumed
	// inside NewRecord's sha256(salt‖secret) step and held in the returned SecretKey
	// whose raw field is unexported. We hold the sk+rec here in locals; they are
	// discarded (returned as zero values) if the audit Emit fails in step 2.
	sk, err := e.minter.Mint()
	if err != nil {
		return SecretKey{}, Record{}, fmt.Errorf("mcpkey: mint: %w", err)
	}

	var expiry time.Time
	if expiresAt != nil {
		expiry = *expiresAt
	}
	rec, err := NewRecord(sk, tenant, deployment, expiry, e.clk)
	if err != nil {
		return SecretKey{}, Record{}, fmt.Errorf("mcpkey: build record: %w", err)
	}

	// Step 2: Audit FIRST, fail-closed. The Record carries key_id for correlation —
	// NEVER the raw sk-ocu- key (the never-logged guard enforces this structurally).
	// The Caller and Tenant come from scope.Identity() — the host-attested operator
	// (NFR-SEC-43); the tenant argument is the operator-chosen TARGET, not the actor.
	// A non-nil Emit result is a hard deny: return zero values with no side effects.
	auditRec := audit.Record{
		Action:  audit.ActionMCPKeyCreate,
		Channel: ingress.ChannelOperator.String(),
		Key:     rec.KeyID, // key_id for correlation — NEVER the raw secret
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
	}
	if err := e.audit.Emit(ctx, auditRec); err != nil {
		// Hard deny: discard the minted sk and record; return nothing to the caller.
		// Nothing is persisted or published — the audit trail can never lag the effect.
		return SecretKey{}, Record{}, fmt.Errorf("mcpkey: create audit: %w", err)
	}

	// Step 3: Persist the record to the store.
	if err := e.store.Put(ctx, rec); err != nil {
		return SecretKey{}, Record{}, fmt.Errorf("mcpkey: store put: %w", err)
	}

	// Step 4: Re-render the artifact from the current live set. The new key is now
	// in ActiveRecords; the artifact includes it.
	if e.rerender != nil {
		if err := e.rerender(ctx); err != nil {
			return SecretKey{}, Record{}, fmt.Errorf("mcpkey: rerender: %w", err)
		}
	}

	// Step 5: Return the shown-once SecretKey. The caller's CLI render calls
	// sk.Reveal() at the single display site; after that the raw key is gone.
	return sk, rec, nil
}

// Revoke flips the status of the record identified by keyID to StatusRevoked and
// re-renders the artifact so the revoked key is omitted from the published boot-set
// immediately. It is AUDIT-FIRST and fail-closed: the Record (ActionMCPKeyRevoke)
// is emitted BEFORE the status flip, and a non-nil Emit result DENIES the revoke —
// the record is left active if the audit write fails (NFR-SEC-45).
//
// The scope parameter is the operator capability (NFR-SEC-52), mirroring
// killswitch.Engine.RevokeOne. keyID is the public handle the operator passes to
// "revoke --id"; reason is operator-supplied context for the trail.
func (e *Engine) Revoke(ctx context.Context, scope ingress.OperatorScope, keyID, reason string) error {
	if !scope.Valid() {
		return ErrScopeInvalid
	}

	// Audit FIRST, fail-closed: the revoke's record must be durable before the
	// status is flipped and the artifact re-rendered. A write failure DENIES the
	// revoke so the durable posture and the audit trail can never disagree. The Key
	// carries the key_id for correlation (never the raw secret). The audit actor is
	// WHO ACTED — the host-attested operator stamped onto the scope at mint.
	rec := audit.Record{
		Action:  audit.ActionMCPKeyRevoke,
		Channel: ingress.ChannelOperator.String(),
		Key:     keyID,
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
		Reason:  reason,
	}
	if err := e.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("mcpkey: revoke audit: %w", err)
	}

	// Flip the record status to revoked in the store. The store's Revoke is
	// idempotent: revoking an already-revoked or absent key_id is a no-op.
	if err := e.store.Revoke(ctx, keyID); err != nil {
		return fmt.Errorf("mcpkey: store revoke: %w", err)
	}

	// Re-render the artifact. The revoked key is now absent from ActiveRecords, so
	// the re-rendered artifact omits it — Control's half of the ≤5-min revoke
	// budget (NFR-SEC-04). The gateway refresh (component-01) handles propagation.
	if e.rerender != nil {
		if err := e.rerender(ctx); err != nil {
			return fmt.Errorf("mcpkey: rerender: %w", err)
		}
	}

	return nil
}
