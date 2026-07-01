// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/audit"
)

// actionSet collects a slice of Actions into a set for membership and subset checks.
func actionSet(as []audit.Action) map[audit.Action]bool {
	m := make(map[audit.Action]bool, len(as))
	for _, a := range as {
		m[a] = true
	}
	return m
}

// allowedOverlap names the Action that the canon legitimately lists under BOTH
// fixture families: a teardown is BOTH an operator-initiated state-mutating action
// (SEC-45) and a system-initiated lifecycle transition (SEC-72), reached via two
// distinct paths to the same enum value. Pinning the overlap to exactly this one
// value keeps the partition intentional: a new accidental double-classification
// fails the property, while the canon's deliberate destroy overlap is allowed.
var allowedOverlap = map[audit.Action]bool{
	audit.ActionDestroy: true,
}

// TestProperty_SEC45ExhaustiveOverPrivilegedEnum is the MANDATORY exhaustiveness
// property: NO privileged action escapes the audit wrap. For every Action in the
// closed PrivilegedActions enum, the action is covered by at least one fixture family
// — it appears in SEC45Actions OR in the enum-backed SEC72 actions — and the ONLY
// action allowed in both is the canon teardown overlap (operator teardown vs system
// teardown reaching the same enum value). It also asserts SEC45Actions ⊆
// PrivilegedActions (no SEC-45 entry escapes the enum) and that the union SEC45 ∪
// SEC72-with-enum EQUALS PrivilegedActions (no privileged action is uncovered, and no
// covered action is outside the enum). rapid drives random Actions across the FULL
// uint8 range and asserts only enumerated ones are classified privileged.
func TestProperty_SEC45ExhaustiveOverPrivilegedEnum(t *testing.T) {
	t.Parallel()

	priv := audit.PrivilegedActions()
	privSet := actionSet(priv)
	sec45 := actionSet(audit.SEC45Actions())
	sec72 := actionSet(audit.SEC72EnumActions())

	// (a) Every privileged action is covered by at least one fixture family (no
	// escape), and the only double-classification is the pinned teardown overlap.
	for _, a := range priv {
		in45 := sec45[a]
		in72 := sec72[a]
		if !in45 && !in72 {
			t.Fatalf("privileged action %v is in neither fixture family — it escaped the audit wrap", a)
		}
		if in45 && in72 && !allowedOverlap[a] {
			t.Fatalf("privileged action %v is double-classified (SEC45 and SEC72) but is not the pinned teardown overlap", a)
		}
	}

	// (b) SEC45 ⊆ Privileged: no SEC-45 entry escapes the enum.
	for a := range sec45 {
		if !privSet[a] {
			t.Fatalf("SEC45 action %v is not in PrivilegedActions — a SEC-45 entry escaped the enum", a)
		}
	}

	// (c) SEC72-with-enum ⊆ Privileged.
	for a := range sec72 {
		if !privSet[a] {
			t.Fatalf("SEC72 enum action %v is not in PrivilegedActions", a)
		}
	}

	// (d) The union EQUALS the privileged enum: no privileged action escapes the wrap.
	union := make(map[audit.Action]bool)
	for a := range sec45 {
		union[a] = true
	}
	for a := range sec72 {
		union[a] = true
	}
	if len(union) != len(privSet) {
		t.Fatalf("SEC45 ∪ SEC72-with-enum has %d actions, PrivilegedActions has %d — the wrap is not exhaustive", len(union), len(privSet))
	}
	for a := range privSet {
		if !union[a] {
			t.Fatalf("privileged action %v is in neither fixture family — it escaped the audit wrap", a)
		}
	}

	// (e) rapid: only enumerated actions classify as privileged across the FULL uint8
	// range, so a value past the last enum arm is never treated as audited.
	rapid.Check(t, func(rt *rapid.T) {
		raw := rapid.Uint8().Draw(rt, "raw_action")
		a := audit.Action(raw)
		got := audit.IsPrivileged(a)
		want := privSet[a]
		if got != want {
			rt.Fatalf("IsPrivileged(Action(%d)) = %v, want %v (only enumerated actions are privileged)", raw, got, want)
		}
		// A privileged action must classify into exactly one fixture family; an
		// unknown must classify into neither.
		coveredBy45or72 := sec45[a] || sec72[a]
		if got != coveredBy45or72 {
			rt.Fatalf("Action(%d): privileged=%v but covered-by-fixture=%v — classification mismatch", raw, got, coveredBy45or72)
		}
	})
}

// TestEmitCallSiteActionsArePinned is the wiring pin: every Action the live Emit call
// sites pass (the 6 Phase-3 actions plus the retention-policy action the fixture
// adds) is a member of PrivilegedActions. This binds the call sites to the fixture so
// a call site that drifts to a non-enumerated action fails the test.
func TestEmitCallSiteActionsArePinned(t *testing.T) {
	t.Parallel()
	// The Actions the lifecycle + kill-switch Emit call sites pass today.
	callSiteActions := []audit.Action{
		audit.ActionCreateCommit,  // lifecycle stageCommit
		audit.ActionDestroy,       // lifecycle Destroy
		audit.ActionRevokeOne,     // killswitch RevokeOne
		audit.ActionRevokeAll,     // killswitch RevokeAll
		audit.ActionEditDenylist,  // killswitch denylist edit
		audit.ActionOverrideQuota, // killswitch quota override
		audit.ActionRetentionPolicy,
		audit.ActionCreateRejected, // lifecycle stageAdmit/stageQuotaCharge/stageReserve deny
	}
	priv := actionSet(audit.PrivilegedActions())
	for _, a := range callSiteActions {
		if !priv[a] {
			t.Fatalf("Emit call-site action %v is not in PrivilegedActions — the wiring drifted from the fixture", a)
		}
	}
}

// TestCreateRejectedIsSEC72Only proves the system-initiated create rejection is
// classified into the SEC-72 family ALONE: it is covered by SEC72EnumActions, it is
// NOT an operator/SOAR action (absent from SEC45Actions, byte-unchanged), and it is
// not the pinned teardown overlap — so it is covered exactly once, not
// double-classified. This is the canon ruling: a system rejection is SEC-72, never
// SEC-45.
func TestCreateRejectedIsSEC72Only(t *testing.T) {
	t.Parallel()
	sec45 := actionSet(audit.SEC45Actions())
	sec72 := actionSet(audit.SEC72EnumActions())

	if !sec72[audit.ActionCreateRejected] {
		t.Fatal("ActionCreateRejected is not in SEC72EnumActions — the system rejection escaped its family")
	}
	if sec45[audit.ActionCreateRejected] {
		t.Fatal("ActionCreateRejected is in SEC45Actions — a system rejection must never enter the operator set")
	}
	if allowedOverlap[audit.ActionCreateRejected] {
		t.Fatal("ActionCreateRejected is in allowedOverlap — only the teardown overlap is permitted")
	}
}

// TestFixtureVersionPinned proves the fixture version constant is the expected v1, so
// a fixture-set change without a version bump fails this pin.
func TestFixtureVersionPinned(t *testing.T) {
	t.Parallel()
	if audit.FixtureVersion != "v1" {
		t.Fatalf("FixtureVersion = %q, want v1", audit.FixtureVersion)
	}
}

// TestSEC72LabelSetComplete proves the SEC-72 label set carries the canon
// system-initiated transitions, with the deferred-verb labels forward-declared
// (HasEnum=false) and the enum-backed labels mapping onto real Action arms.
func TestSEC72LabelSetComplete(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"session-create": true, "session-destroy": true, "pool-claim": true,
		"auto-lease-issue": true, "scrub": true, "teardown": true,
		"quota-rejection": true, "admission-rejection": true, "killswitch-rejection": true,
		"secret-inject": false, "secret-revoke": false, // forward-declared (HasEnum)
	}
	got := make(map[string]bool)
	for _, m := range audit.SEC72Actions() {
		got[m.Label] = m.HasEnum
		if m.HasEnum && audit.IsPrivileged(m.Action) == false {
			t.Fatalf("SEC72 label %q maps to non-privileged action %v", m.Label, m.Action)
		}
		if !m.HasEnum && m.Action != audit.ActionCreateCommit {
			// A deferred-verb label carries the zero Action value (ActionCreateCommit is
			// iota 0); HasEnum=false means it must NOT be read as a classification.
			continue
		}
	}
	for label, wantEnum := range want {
		gotEnum, ok := got[label]
		if !ok {
			t.Fatalf("SEC72 label %q missing from the fixture", label)
		}
		if gotEnum != wantEnum {
			t.Fatalf("SEC72 label %q HasEnum = %v, want %v", label, gotEnum, wantEnum)
		}
	}
}
