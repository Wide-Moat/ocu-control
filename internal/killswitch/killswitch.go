// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package killswitch is the host-initiated revoke engine (NFR-SEC-01): it AUTHORS
// the durable deny posture and force-kills live sessions, reachable ONLY from the
// operator ingress. Every Engine method takes an ingress.OperatorScope as a required
// parameter, so a gateway caller — which can obtain no such value — cannot even FORM
// a call to a revoke. Control AUTHORS the denylist; the Egress trust-edge READS it
// and enforces (enforcement is not in this package).
//
// Two reaches, one engine. RevokeOne denylists a single session key (ScopeSession);
// RevokeAll engages DENY-ALL (ScopeGlobal) and force-kills EVERY live row; ResumeAll
// is the symmetric in-band counterpart to RevokeAll — the operator-only lift of the
// deployment-wide DENY-ALL. All are AUDIT-FIRST and fail-closed: the audit Record is
// emitted BEFORE the durable posture is mutated, and if the AuditSink fails the
// action is DENIED and the posture is left untouched — the audit trail can never lag
// the effect it records. The force-kill step MUST include RESERVED rows, not only
// ACTIVE ones, so a just-reserved-not-yet-committed session cannot survive a
// DENY-ALL.
//
// SOAR verify-then-mint. The operator adapter runs SOARVerifier.Verify BEFORE it
// mints the OperatorScope, so an unverifiable SOAR signature yields no scope and
// thus cannot even form an Engine call — "acting" is structurally impossible before
// "verified". The admin-API and CLI channels authenticate at the operator ingress
// (operator credential / host-owned socket peer creds) instead.
//
// The revoke path is a bounded, reserved-priority path distinct from the create
// ingress: it does the minimum work (one SetDeny plus the force-kill sweep) on the
// operator socket, which a create flood on the gateway TCP port cannot starve
// (NFR-SEC-55). Enforcement of that priority is the operator adapter's worker-pool
// concern; the Engine keeps the revoke body O(1) on the Store write so it never
// blocks on a create lock.
package killswitch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// forceKillStepTimeout bounds each force-kill finalizer call run during a RevokeAll
// sweep, so one wedged daemon call cannot stall the revoke of every other session.
// It mirrors the bounded per-step discipline the runtime finalizer and the lifecycle
// unwind use.
const forceKillStepTimeout = 5 * time.Second

// ErrScopeInvalid is the fail-closed refusal when an Engine method is called with an
// OperatorScope that is not a genuine minted scope (the inert zero value, or one
// minted from a forged zero-value seam). The compile-time seal makes a gateway call
// impossible to form; this is the runtime backstop against a zero-value scope passed
// by reflection or an accidental struct copy. Callers match it with errors.Is.
var ErrScopeInvalid = errors.New("killswitch: operator scope invalid, revoke refused (fail-closed)")

// ErrSOARUnverified is returned when a SOAR webhook signature cannot be verified
// against the SOAR principal. The operator adapter checks this BEFORE minting an
// OperatorScope, so an unverifiable SOAR call never reaches the Engine; the sentinel
// lives here so the verify path and the revoke path share one typed refusal
// (P2-R2). Callers match it with errors.Is.
var ErrSOARUnverified = errors.New("killswitch: SOAR signature unverifiable, revoke rejected (P2-R2)")

// ConcurrencyRefunder returns one per-tenant DimConcurrentSessions slot for a row the
// kill-switch force-killed. It is the SAME single decrement lifecycle.Destroy and the
// boot reconciler use (quota.Gate.RefundConcurrent) — a negative-delta Charge the
// Store saturates at zero, so a double refund never drives the counter negative. The
// kill path MUST call it: without it the level counter is a write-only ratchet on
// force-kill (charged on create, never returned on an emergency revoke), and after a
// RevokeAll the tenant's slot stays charged with zero live rows, refusing every later
// create with ErrQuotaExceeded against a phantom count.
type ConcurrencyRefunder interface {
	RefundConcurrent(ctx context.Context, tenant state.Identity) error
}

// Engine authors the durable denylist (state.Store.SetDeny) and force-kills live
// rows. It is reachable ONLY from the operator ingress: every method takes an
// ingress.OperatorScope, so no gateway route can form a call. It holds the Store (to
// author the deny posture), the registry Custodian (to enumerate live rows and drive
// a force-killed row to the RELEASED tombstone), the runtime provider (the force-kill
// finalizer), the injected Clock (the deny entry's Since stamp), the fail-closed audit
// sink, and the concurrency refunder (to return the level-counter slot a force-kill
// frees, the SAME decrement the destroy and reconcile paths use).
type Engine struct {
	store    state.Store
	reg      *registry.Custodian
	provider runtime.RuntimeProvider
	clk      state.Clock
	audit    audit.AuditSink
	refund   ConcurrencyRefunder
}

// NewEngine constructs an Engine from its collaborators. The same Clock the Store
// was built with must be passed so the whole revoke path reads time through one
// seam. The refunder is the quota.Gate that also charged the counter on create, so
// the force-kill returns the level slot through the one decrement path the destroy
// and reconcile paths share.
func NewEngine(store state.Store, reg *registry.Custodian, provider runtime.RuntimeProvider, clk state.Clock, sink audit.AuditSink, refund ConcurrencyRefunder) *Engine {
	return &Engine{
		store:    store,
		reg:      reg,
		provider: provider,
		clk:      clk,
		audit:    sink,
		refund:   refund,
	}
}

// RevokeOne denylists a single session key (ScopeSession) and force-kills its live
// row if present. It is AUDIT-FIRST and fail-closed: the Record is emitted BEFORE
// the deny is authored, and an AuditSink failure DENIES the revoke (no SetDeny, no
// force-kill). The scope parameter is the operator capability — a gateway caller
// cannot obtain one, so this method is unreachable from a gateway route; the Valid
// check is the runtime backstop to the compile-time seal. key is the host-derived
// reservation key string (from Key.String()); reason is operator-supplied context
// for the audit trail.
func (e *Engine) RevokeOne(ctx context.Context, scope ingress.OperatorScope, key, reason string) error {
	if !scope.Valid() {
		return ErrScopeInvalid
	}

	// Audit FIRST, fail-closed: the record must be durable before the deny is
	// authored. A write failure denies the revoke and authors nothing. The audit
	// actor (actor.user) is WHO ACTED — the host-attested operator stamped onto the
	// scope at mint (peer-cred for admin/CLI, SOAR principal for SOAR), never a
	// request-body hint (NFR-SEC-43).
	rec := audit.Record{
		Action:  audit.ActionRevokeOne,
		Channel: ingress.ChannelOperator.String(),
		Key:     key,
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
		Reason:  reason,
	}
	if err := e.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("killswitch: revoke-one audit: %w", err)
	}

	// Author the durable per-session deny entry. Reserve re-checks the posture inside
	// its advisory lock, so a create racing this revoke still refuses at S4.
	entry := state.DenyEntry{
		Scope:  state.ScopeSession,
		Key:    key,
		Reason: reason,
		Since:  e.clk.Now(),
	}
	if err := e.store.SetDeny(ctx, entry); err != nil {
		return fmt.Errorf("killswitch: revoke-one set deny: %w", err)
	}

	// Force-kill the live row if one exists. A row absent from the live set is already
	// gone; a substrate already-gone is idempotent. A force-kill failure does not undo
	// the durable deny — the deny is the authoritative kill, the substrate reclaim is
	// best-effort and reconciled at next boot.
	if err := e.forceKillKey(ctx, key); err != nil {
		return fmt.Errorf("killswitch: revoke-one force-kill: %w", err)
	}
	return nil
}

// RevokeAll engages the deployment-wide DENY-ALL (ScopeGlobal) and force-kills EVERY
// live (RESERVED+ACTIVE) row — RESERVED included, so a just-reserved-not-yet-
// committed session cannot survive. It is AUDIT-FIRST and fail-closed: the Record is
// emitted BEFORE DENY-ALL is engaged, and an AuditSink failure DENIES the revoke. The
// scope parameter is the operator capability the gateway cannot obtain. The
// enumeration is fail-closed: a Store that cannot list live rows surfaces
// registry.ErrEnumerationUnsupported rather than silently treating an empty list as
// "no live rows" and leaving a session alive.
func (e *Engine) RevokeAll(ctx context.Context, scope ingress.OperatorScope, reason string) error {
	if !scope.Valid() {
		return ErrScopeInvalid
	}

	// Audit FIRST, fail-closed: a DENY-ALL is the most privileged op; its record must
	// be durable before the posture is engaged. The Key is empty (this targets every
	// session, not one). The audit actor (actor.user) is WHO ACTED — the host-attested
	// operator stamped onto the scope at mint, never a request-body hint (NFR-SEC-43).
	rec := audit.Record{
		Action:  audit.ActionRevokeAll,
		Channel: ingress.ChannelOperator.String(),
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
		Reason:  reason,
	}
	if err := e.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("killswitch: revoke-all audit: %w", err)
	}

	// Engage DENY-ALL. From this point every create is refused at Reserve against real
	// durable state, so no NEW session can race the force-kill sweep below.
	entry := state.DenyEntry{
		Scope:  state.ScopeGlobal,
		Reason: reason,
		Since:  e.clk.Now(),
	}
	if err := e.store.SetDeny(ctx, entry); err != nil {
		return fmt.Errorf("killswitch: revoke-all set deny: %w", err)
	}

	// Enumerate and force-kill EVERY live row. The enumeration is fail-closed: an
	// unsupported Store surfaces the typed error rather than leave a session alive.
	rows, err := e.reg.ReservedAndActiveKeys(ctx)
	if err != nil {
		return fmt.Errorf("killswitch: revoke-all enumerate live rows: %w", err)
	}
	var firstErr error
	for i := range rows {
		if err := e.forceKillRow(ctx, rows[i]); err != nil && firstErr == nil {
			// Record the first reclaim error but continue: one wedged session must not
			// strand the force-kill of every other. DENY-ALL is the authoritative kill;
			// the reconciler reclaims any residue at next boot.
			firstErr = fmt.Errorf("killswitch: revoke-all force-kill %q: %w", rows[i].Key, err)
		}
	}
	return firstErr
}

// ResumeAll is the operator-only in-band LIFT of the deployment-wide DENY-ALL
// (ScopeGlobal) — the symmetric counterpart to RevokeAll. It is AUDIT-FIRST and
// fail-closed: the Record (ActionResumeGlobal) is emitted BEFORE the global deny is
// cleared, and an AuditSink failure DENIES the resume so the durable posture and the
// audit trail can never disagree. The scope parameter is the operator capability the
// gateway cannot obtain; the Valid check is the runtime backstop to the compile-time
// seal. An operator who engaged a global kill-switch lifts it ONLY through this path
// — it is never folded into a per-session denylist edit (that is LiftDeny, which
// lifts ScopeSession only and refuses an empty key). There is no force-kill sweep:
// ResumeAll only lifts the durable bar, and Reserve consults the same Store, so the
// restored admit-posture is enforced implicitly. reason is operator-supplied context
// for the audit trail.
func (e *Engine) ResumeAll(ctx context.Context, scope ingress.OperatorScope, reason string) error {
	if !scope.Valid() {
		return ErrScopeInvalid
	}

	// Audit FIRST, fail-closed: the lift's record must be durable before the global
	// deny is cleared. A write failure denies the resume and clears nothing. The Key
	// is empty (a global lift targets every session, exactly like RevokeAll). The
	// audit actor (actor.user) is WHO ACTED — the host-attested operator stamped onto
	// the scope at mint, never a request-body hint (NFR-SEC-43).
	rec := audit.Record{
		Action:  audit.ActionResumeGlobal,
		Channel: ingress.ChannelOperator.String(),
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
		Reason:  reason,
	}
	if err := e.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("killswitch: resume-all audit: %w", err)
	}

	// Lift the deployment-wide DENY-ALL. The empty key is the documented ScopeGlobal
	// key; ClearDeny is idempotent against an absent entry, so a double resume (or a
	// resume with no global deny engaged) is a harmless no-op that still records the
	// attempted operator action.
	if err := e.store.ClearDeny(ctx, state.ScopeGlobal, ""); err != nil {
		return fmt.Errorf("killswitch: resume-all clear: %w", err)
	}
	return nil
}

// forceKillKey reclaims the substrate for a single session key on the RevokeOne path.
// It looks the row up without the advisory lock; a missing row is already gone (no
// reclaim owed). A present row is force-killed and driven to the RELEASED tombstone.
func (e *Engine) forceKillKey(ctx context.Context, key string) error {
	row, err := e.store.LookupSession(ctx, key)
	if err != nil {
		if errors.Is(err, state.ErrReservationNotFound) {
			// No live row: the session is already gone, nothing to reclaim.
			return nil
		}
		return fmt.Errorf("lookup session: %w", err)
	}
	if row.State == state.StateReleased {
		// Already a tombstone: nothing live to force-kill.
		return nil
	}
	return e.forceKillRow(ctx, row)
}

// forceKillRow force-removes the substrate for one row and drives it to the RELEASED
// tombstone via the Custodian. The finalizer is force-remove-authoritative and
// idempotent — an already-gone container maps to ErrNoSuchContainer, treated as a
// satisfied kill — and runs under a bounded per-step timeout so one wedged call
// cannot stall the sweep. Releasing through the Custodian keeps the four Store
// mutators custodied in one type and is idempotent against an already-released row.
func (e *Engine) forceKillRow(ctx context.Context, row state.SessionRow) error {
	// The teardown Sandbox carries the host-derived session key on Egress.FilesystemID
	// so the shared below-seam finalizer step-1 (revoke session JWT) can look up the
	// jti the create-path mint recorded against that same key. This mirrors
	// lifecycle.Destroy exactly: the frozen session row does not persist the real
	// filesystem_id, so the revocation handle is the host-derived session key both the
	// create and the kill paths derive — never a body hint (NFR-SEC-43). Without this
	// the emergency kill-switch would force-remove the container but leave the weak
	// Storage-JWT live until its TTL, the exact authority the host-initiated revoke
	// exists to cut (NFR-SEC-01).
	sandbox := runtime.Sandbox{
		Name:      runtime.SessionName(row.Key),
		RuntimeID: row.ContainerName,
		Egress:    runtime.EgressBinding{Name: runtime.SessionName(row.Key), FilesystemID: row.Key},
	}
	stepCtx, cancel := context.WithTimeout(ctx, forceKillStepTimeout)
	defer cancel()
	if err := e.provider.Teardown().ForceKill(stepCtx, sandbox); err != nil {
		if !errors.Is(err, runtime.ErrNoSuchContainer) {
			return fmt.Errorf("force-kill sandbox: %w", err)
		}
	}
	if _, err := e.reg.ForceReleaseRow(ctx, row); err != nil {
		// An already-released row is idempotent inside the Store; a real release fault is
		// surfaced so the sweep records it.
		return fmt.Errorf("release force-killed row: %w", err)
	}
	// Return the per-tenant concurrency slot the force-kill frees, the SAME decrement
	// lifecycle.Destroy and the boot reconciler use. Without this the level counter is a
	// write-only ratchet on the kill path: charged on create, never returned on an
	// emergency revoke, so the tenant's slot stays charged with zero live rows and every
	// later create is refused ErrQuotaExceeded against a phantom count. The refund keys
	// on the ROW OWNER (the tenant the create charged), never the operator actor, and is
	// idempotent — the Store saturates the negative delta at zero, so ForceReleaseRow's
	// already-released idempotence and a re-run of the sweep never drive the count below
	// the true live count.
	if err := e.refund.RefundConcurrent(ctx, row.Owner); err != nil {
		return fmt.Errorf("refund force-killed concurrency: %w", err)
	}
	return nil
}

// LiftDeny is the operator denylist-edit: it lifts a previously authored
// per-session deny entry (ScopeSession) so a wrongly-denied session can be
// admitted again. It is AUDIT-FIRST and fail-closed exactly as the revoke path is —
// the Record (ActionEditDenylist) is emitted BEFORE ClearDeny runs, and an
// AuditSink failure DENIES the edit so the durable posture and the audit trail can
// never disagree. It takes an OperatorScope, so it is reachable only from the
// operator ingress; the Valid check is the runtime backstop to the compile-time
// seal. It deliberately does NOT lift the deployment-wide DENY-ALL: a global
// kill-switch is cleared through a distinct, explicit operator path, never folded
// into a per-session denylist edit. key is the host-derived reservation key string;
// reason is operator-supplied context for the audit trail.
func (e *Engine) LiftDeny(ctx context.Context, scope ingress.OperatorScope, key, reason string) error {
	if !scope.Valid() {
		return ErrScopeInvalid
	}
	if key == "" {
		// A denylist edit addresses a single session; an empty key would target the
		// global posture, which this path refuses to touch.
		return fmt.Errorf("killswitch: lift-deny requires a session key (global DENY-ALL is not lifted here)")
	}

	// Audit FIRST, fail-closed: the edit's record must be durable before the deny is
	// lifted. A write failure denies the edit and clears nothing. The audit actor
	// (actor.user) is WHO ACTED — the host-attested operator stamped onto the scope at
	// mint, never a request-body hint (NFR-SEC-43).
	rec := audit.Record{
		Action:  audit.ActionEditDenylist,
		Channel: ingress.ChannelOperator.String(),
		Key:     key,
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
		Reason:  reason,
	}
	if err := e.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("killswitch: lift-deny audit: %w", err)
	}

	// Lift the per-session deny entry. ClearDeny is idempotent against an absent
	// entry, so a double edit is harmless.
	if err := e.store.ClearDeny(ctx, state.ScopeSession, key); err != nil {
		return fmt.Errorf("killswitch: lift-deny clear: %w", err)
	}
	return nil
}

// OverrideQuota is the operator quota-override: it applies an operator-authored
// delta to a single counter cell (e.g. to release a stuck concurrent-session slot
// or grant burst headroom) through the SAME atomic Store.Charge the gate uses, so
// the override can never drive a counter negative (a negative delta saturates at
// zero) and a positive delta is still bounded by the supplied limit. It is
// AUDIT-FIRST and fail-closed: the Record (ActionOverrideQuota) is emitted BEFORE
// the Charge, and an AuditSink failure DENIES the override so no counter moves
// without a durable record. It takes an OperatorScope, so it is reachable only from
// the operator ingress. The identity and dimension are host-supplied by the
// operator adapter (never a gateway body); reason is the audit context.
func (e *Engine) OverrideQuota(ctx context.Context, scope ingress.OperatorScope, key state.QuotaKey, delta, limit int64, reason string) error {
	if !scope.Valid() {
		return ErrScopeInvalid
	}

	// Audit FIRST, fail-closed: the override's record must be durable before any
	// counter moves. The audit actor (actor.user) is WHO ACTED — the host-attested
	// OPERATOR who issued the override (scope.Identity), NOT the quota TARGET
	// (key.Identity, the tenant whose counter moves). The target is the OBJECT of the
	// action, not its subject; stamping it as the actor would mislabel the override's
	// author as its victim. The Charge below still targets key, so the target cell is
	// correct; only the audit actor source is the operator (NFR-SEC-43).
	rec := audit.Record{
		Action:  audit.ActionOverrideQuota,
		Channel: ingress.ChannelOperator.String(),
		Caller:  scope.Identity().Caller,
		Tenant:  scope.Identity().Tenant,
		Reason:  reason,
	}
	if err := e.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("killswitch: override-quota audit: %w", err)
	}

	// Apply the operator-authored delta through the atomic Charge. A negative delta
	// saturates at zero in the Store; a positive delta is bounded by limit and may
	// return ErrQuotaExceeded, which propagates as the typed refusal.
	if _, err := e.store.Charge(ctx, key, delta, limit); err != nil {
		return fmt.Errorf("killswitch: override-quota charge: %w", err)
	}
	return nil
}

// SOARVerifier verifies a SOAR webhook signature against the SOAR principal BEFORE
// the operator adapter mints the OperatorScope (verify-then-mint). An unverifiable
// call yields no scope and thus cannot even form an Engine call. The admin-API and
// CLI channels authenticate at the operator ingress instead, so every channel is
// authenticated before authoring a revoke.
type SOARVerifier interface {
	// Verify returns the verified SOAR PRINCIPAL identity and a nil error only when
	// sig is a valid signature over payload from that principal; any other outcome
	// returns the zero Identity and ErrSOARUnverified (or a wrapped cause). The
	// principal is the AUTHORITY for a SOAR-driven revoke (P2-R2): it — not the
	// unix-socket peer that delivered the webhook — is the audit actor, so the
	// operator adapter mints the OperatorScope with this identity. The context is
	// first per repo convention.
	Verify(ctx context.Context, payload, sig []byte) (state.Identity, error)
}
