// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package audit defines the AuditSink seam: the single emit contract the control
// plane welds every privileged operator/SOAR action to. The load-bearing rule is
// fail-closed — a privileged action is denied if its audit record cannot be made
// durable before the action is acknowledged, so the audit trail can never lag the
// effect it records (NFR: every privileged op emits a chain-linked event BEFORE
// ack; deny if the audit write fails).
//
// This package defines the PORT and the fail-closed-on-emit-failure BRANCH,
// exercised on every privileged op: the operator/SOAR actions (create-commit,
// destroy, revoke-one, revoke-all, denylist-edit, quota-override) and the
// system-initiated create-rejected record (NFR-SEC-46/72). The OCSF serializer
// that maps each Record to an API Activity event (class_uid 6003) and hash-chains
// the durable spine lives in internal/audit/ocsf behind this exact interface; the
// Record fields here are who, what, which session, and the host-derived identity.
// A RecordingFake with a fault mode ships so the deny-on-emit-failure path is
// unit-exercised rather than asserted on faith.
//
// The package is a leaf: it imports nothing internal, so every layer above can
// hold the AuditSink without dragging the lifecycle, registry, or state seams
// into its import graph.
package audit

import (
	"context"
	"errors"
)

// Action names a privileged operation whose record must be durable before the
// action is acknowledged. The set is CLOSED: a new privileged op adds a value
// here, and the String method below must grow with it. It is a label for the
// audit record, never a comparison subject for an authority decision.
type Action uint8

const (
	// ActionCreateCommit is a session create reaching its Commit checkpoint — the
	// single privileged checkpoint on the create path that must be audited before
	// the create is acknowledged.
	ActionCreateCommit Action = iota
	// ActionDestroy is a session teardown.
	ActionDestroy
	// ActionRevokeOne is a kill-switch revoke of a single session.
	ActionRevokeOne
	// ActionRevokeAll is a kill-switch DENY-ALL engage.
	ActionRevokeAll
	// ActionEditDenylist is an operator denylist edit.
	ActionEditDenylist
	// ActionOverrideQuota is an operator quota override.
	ActionOverrideQuota
	// ActionRetentionPolicy is an operator/SOAR retention-policy change. It is a
	// state-mutating operator action named explicitly in the SEC-45 privileged-action
	// fixture; it has its own enum arm so the exhaustiveness property can prove no
	// privileged action escapes the audit wrap. Its wire surface (the operator route
	// that drives it) is a deferred follow-up; the enum value exists now so the audit
	// classification is closed over every privileged action the fixture names.
	ActionRetentionPolicy
	// ActionResumeGlobal is an operator LIFT of the deployment-wide DENY-ALL — the
	// in-band counterpart to ActionRevokeAll. It is an operator state-mutating
	// action (the SEC-45 family), audited fail-closed before the durable global
	// deny is cleared. It is inserted BEFORE ActionCreateRejected so the latter
	// stays the last enum arm and the exhaustiveness boundary proof
	// (lastAction + the "audit_action_unknown" one-past-the-end value) holds.
	ActionResumeGlobal
	// ActionMCPKeyCreate is an operator mint of a new sk-ocu- MCP API key. It is
	// an operator state-mutating action (the SEC-45 family), audited fail-closed
	// BEFORE the key is minted, persisted, or published — a key that is live but
	// un-recorded violates NFR-SEC-45. Inserted BEFORE ActionCreateRejected so
	// the boundary anchor stays last.
	ActionMCPKeyCreate
	// ActionMCPKeyRevoke is an operator revocation of an existing sk-ocu- MCP API
	// key. It is an operator state-mutating action (the SEC-45 family), audited
	// fail-closed BEFORE the record status is flipped and the artifact re-rendered.
	// Inserted BEFORE ActionCreateRejected so the boundary anchor stays last.
	ActionMCPKeyRevoke
	// ActionCreateRejected is a session create REFUSED at a pre-side-effect deny
	// stage (admission, quota, or the kill-switch/denylist re-check). It is the
	// system-initiated rejection record NFR-SEC-46/72 require: the deny itself is
	// audited fail-closed before the typed rejection reaches the caller. It is NOT
	// an operator action and never enters the SEC-45 set.
	ActionCreateRejected
)

// String renders the Action for the audit record and for diagnostics. An
// out-of-range value renders as "audit_action_unknown" rather than a bogus
// label, so a forgotten String arm surfaces in the record instead of silently
// mislabelling.
func (a Action) String() string {
	switch a {
	case ActionCreateCommit:
		return "create_commit"
	case ActionDestroy:
		return "destroy"
	case ActionRevokeOne:
		return "revoke_one"
	case ActionRevokeAll:
		return "revoke_all"
	case ActionEditDenylist:
		return "edit_denylist"
	case ActionOverrideQuota:
		return "override_quota"
	case ActionRetentionPolicy:
		return "retention_policy"
	case ActionResumeGlobal:
		return "resume_global"
	case ActionMCPKeyCreate:
		return "mcp_key_create"
	case ActionMCPKeyRevoke:
		return "mcp_key_revoke"
	case ActionCreateRejected:
		return "create_rejected"
	default:
		return "audit_action_unknown"
	}
}

// Record is the minimal event shape the sink emits. internal/audit/ocsf produces
// the full OCSF mapping from these fields — the class_uid and the chain hash that
// links each record to its predecessor; the fields here are exactly what the
// fail-closed branch needs: which privileged Action, which ingress Channel it
// arrived on, the host-derived reservation Key the action targets, and the
// host-derived caller and tenant. None of these is ever populated from a request
// body — they are the host-resolved values the layer above already holds.
type Record struct {
	// Action is the privileged operation this record attests.
	Action Action
	// Channel is the ingress the action arrived on ("operator" | "gateway"), set
	// by the layer above from the resolved AuthenticatedCaller.
	Channel string
	// Key is the host-derived reservation key the action targets. It is opaque
	// (for correlation only) and is empty for a DENY-ALL revoke that targets every
	// session rather than one.
	Key string
	// Caller is the host-derived caller principal (Identity.Caller) the action was
	// issued under. Never a body-supplied hint.
	Caller string
	// Tenant is the host-derived tenant (Identity.Tenant) the action billed
	// against. Never a body-supplied hint.
	Tenant string
	// Reason is the operator-supplied reason text for a revoke or override. It is
	// free-form context for the trail, never part of any authority decision.
	Reason string
	// RevokeOutcome is an OPTIONAL evidence detail on a destroy record: the result
	// of the teardown finalizer's step-1 Storage-JWT revoke ("marked_dead",
	// "already_dead", or "none_bound"). It is empty on every record that is not a
	// destroy carrying a recorded revoke outcome — an EMPTY value means the revoke
	// step was not run or not recorded, which is semantically distinct from the
	// "none_bound" outcome (a revoke that ran and bound nothing). It is trail
	// evidence, never an authority-decision input; the OCSF serializer carries it
	// in metadata.unmapped.revoke_outcome behind omitempty so a record without it
	// is byte-identical to before this field existed.
	RevokeOutcome string
}

// ErrAuditWriteFailed is the fail-closed evidence: a privileged action MUST be
// denied when Emit returns this (or any other error). The layer above never
// swallows it — it treats a non-nil Emit result as a hard deny and returns
// without performing the action. Callers match it with errors.Is.
var ErrAuditWriteFailed = errors.New("audit: record write failed, action denied (fail-closed)")

// AuditSink is the emit seam. Emit returns nil ONLY when the record is durably
// recorded; any non-nil error denies the privileged action that called it. The
// OCSF chain sink (internal/audit/ocsf) implements this interface in production;
// RecordingFake is the test double. It is the only audit surface the lifecycle
// and kill-switch layers hold. Every method takes a context.Context first (repo
// convention) and an implementation is safe for concurrent use.
type AuditSink interface {
	// Emit makes rec durable and returns nil, or returns a non-nil error that the
	// caller treats as a fail-closed deny. It MUST NOT report success for a record
	// it did not durably write.
	Emit(ctx context.Context, rec Record) error
}
