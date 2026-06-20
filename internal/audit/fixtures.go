// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// This file encodes the VERSIONED, enumerated privileged-action fixtures the audit
// wrap is proven exhaustive against. The two families — SEC-45 (operator/SOAR
// state-mutating actions) and SEC-72 (system-initiated lifecycle transitions) — are
// in-code data, not values invented at call sites: a new privileged op grows the
// Action enum AND the matching fixture, and the exhaustiveness property fails until
// both are in step, so no privileged action can silently escape the audit wrap.
//
// The fixtures live in the LEAF audit package (stdlib-only imports) so every layer
// above can assert its own Emit call sites against them without dragging the OCSF
// serializer, the chain sink, or any heavier seam into its import graph. The OCSF
// mapping and the hash-chain sink that CONSUME these fixtures live in the
// internal/audit/ocsf sub-package, which depends on this leaf one-directionally.

package audit

// FixtureVersion stamps the enumerated fixture sets below. A change to either set —
// adding a privileged action, reclassifying one between SEC-45 and SEC-72, or adding
// a forward-declared deferred-verb label — is a version bump. It is carried in the
// audit metadata so a downstream fan-in can pin which fixture revision a source was
// running.
const FixtureVersion = "v1"

// lastAction is the highest valid Action enum value. It anchors the exhaustive walk
// of the closed enum: PrivilegedActions enumerates 0..lastAction inclusive, and the
// String "audit_action_unknown" boundary just past it is the second, independent
// proof the walk did not miss a value. It must grow with the const block in
// audit.go; the exhaustiveness property fails loudly if it lags.
const lastAction = ActionRetentionPolicy

// PrivilegedActions returns the CLOSED set of privileged Action enum values, in enum
// order. Every value here MUST be covered by exactly one audit fixture family
// (SEC-45 or SEC-72); the exhaustiveness property enforces that. The set is derived
// from the enum itself — walked 0..lastAction — not hand-listed, so it cannot drift
// from the const block.
func PrivilegedActions() []Action {
	out := make([]Action, 0, int(lastAction)+1)
	for a := Action(0); a <= lastAction; a++ {
		out = append(out, a)
	}
	return out
}

// IsPrivileged reports whether a is an enumerated privileged Action — i.e. it has a
// real String arm (not the out-of-range "audit_action_unknown" sentinel) and falls
// within the closed 0..lastAction enum range. A value past the last enum arm is NOT
// privileged: it is an unknown that must never be classified as audited. The rapid
// exhaustiveness property drives the full uint8 range through this and asserts only
// enumerated values are privileged.
func IsPrivileged(a Action) bool {
	return a <= lastAction && a.String() != "audit_action_unknown"
}

// SEC45Actions returns the operator/SOAR state-mutating privileged actions — the
// SEC-45 fixture family. A force-kill is an operator revoke, and BOTH the
// single-session revoke and the deployment-wide DENY-ALL revoke are operator
// force-kills, so both ActionRevokeOne and ActionRevokeAll are here. The denylist
// edit, the quota override, the operator-initiated teardown (destroy), and the
// retention-policy change are the remaining state-mutating operator/SOAR calls. The
// set is closed and versioned; it is a strict subset of PrivilegedActions.
func SEC45Actions() []Action {
	return []Action{
		ActionRevokeOne,       // force-kill, single session
		ActionRevokeAll,       // force-kill, DENY-ALL engage
		ActionEditDenylist,    // operator denylist edit
		ActionOverrideQuota,   // operator quota override
		ActionDestroy,         // operator-initiated teardown (state-mutating)
		ActionRetentionPolicy, // retention-policy change (deferred wire surface)
	}
}

// ActionMeta is a versioned LABEL entry in the SEC-72 system-initiated lifecycle set.
// It pairs a canon fixture label with the Action enum value the transition emits
// under (when one exists). HasEnum is false for a forward-declared verb whose wire
// contract op is deferred and has no Action arm yet — the fixture stays faithful to
// the canon list without fabricating an enum value the frozen contract has not
// pinned. A label with HasEnum=false carries no audit classification weight in the
// exhaustiveness union (only enum-backed entries cover the privileged enum); it
// documents the canon transition so the set is complete and reviewable.
type ActionMeta struct {
	// Label is the canon name of the system-initiated transition.
	Label string
	// Action is the Action enum value the transition emits under. It is meaningful
	// only when HasEnum is true; otherwise it is the zero value and must not be read.
	Action Action
	// HasEnum reports whether Action is a real enum arm (a transition the audit wrap
	// actually emits today) versus a forward-declared deferred-verb label.
	HasEnum bool
}

// SEC72Actions returns the system-initiated lifecycle transitions — the SEC-72
// fixture family — as a versioned LABEL set. Session create-commit and the
// system-driven teardown map to existing enum arms (ActionCreateCommit,
// ActionDestroy); auto-lease issue and pool-claim land on the create-commit arm
// (they reach the same privileged checkpoint), and scrub/teardown land on the
// destroy arm. The secret inject/revoke verbs are forward-declared with HasEnum=false
// — their wire-contract ops are deferred, so they carry the canon label without an
// invented enum value. The fixture is faithful to the canon transition list while
// only enum-backed entries participate in the exhaustiveness union.
func SEC72Actions() []ActionMeta {
	return []ActionMeta{
		{Label: "session-create", Action: ActionCreateCommit, HasEnum: true},
		{Label: "session-destroy", Action: ActionDestroy, HasEnum: true},
		{Label: "pool-claim", Action: ActionCreateCommit, HasEnum: true},
		{Label: "auto-lease-issue", Action: ActionCreateCommit, HasEnum: true},
		{Label: "scrub", Action: ActionDestroy, HasEnum: true},
		{Label: "teardown", Action: ActionDestroy, HasEnum: true},
		{Label: "secret-inject", HasEnum: false},
		{Label: "secret-revoke", HasEnum: false},
	}
}

// SEC72EnumActions returns the distinct enum-backed Action values the SEC-72 label
// set maps onto, in first-seen order. It is the SEC-72 contribution to the
// exhaustiveness union: the audit wrap covers a privileged action iff that action is
// in SEC45Actions OR SEC72EnumActions. Forward-declared deferred-verb labels carry
// no enum value and are excluded here (they cannot cover an enum value).
func SEC72EnumActions() []Action {
	seen := make(map[Action]bool)
	out := make([]Action, 0, len(SEC72Actions()))
	for _, m := range SEC72Actions() {
		if !m.HasEnum || seen[m.Action] {
			continue
		}
		seen[m.Action] = true
		out = append(out, m.Action)
	}
	return out
}
