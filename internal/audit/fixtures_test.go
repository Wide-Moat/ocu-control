// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
)

// TestPrivilegedActionsIsClosedEnum proves PrivilegedActions walks the closed enum
// 0..lastAction inclusive, returning each value once in enum order and stopping at
// the unknown-String boundary.
func TestPrivilegedActionsIsClosedEnum(t *testing.T) {
	t.Parallel()
	want := []audit.Action{
		audit.ActionCreateCommit,
		audit.ActionDestroy,
		audit.ActionRevokeOne,
		audit.ActionRevokeAll,
		audit.ActionEditDenylist,
		audit.ActionOverrideQuota,
		audit.ActionRetentionPolicy,
	}
	got := audit.PrivilegedActions()
	if len(got) != len(want) {
		t.Fatalf("PrivilegedActions() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PrivilegedActions()[%d] = %v, want %v", i, got[i], want[i])
		}
		if got[i].String() == "audit_action_unknown" {
			t.Fatalf("PrivilegedActions()[%d] renders unknown — the walk overran the enum", i)
		}
	}
}

// TestIsPrivileged proves every enumerated action is privileged and the first
// out-of-range value (lastAction+1) and a far value are not.
func TestIsPrivileged(t *testing.T) {
	t.Parallel()
	for _, a := range audit.PrivilegedActions() {
		if !audit.IsPrivileged(a) {
			t.Fatalf("IsPrivileged(%v) = false, want true", a)
		}
	}
	// One past the last enum value and a far value are NOT privileged.
	beyond := audit.Action(uint8(len(audit.PrivilegedActions())))
	if audit.IsPrivileged(beyond) {
		t.Fatalf("IsPrivileged(%d) = true, want false (one past the last enum arm)", beyond)
	}
	if audit.IsPrivileged(audit.Action(200)) {
		t.Fatal("IsPrivileged(Action(200)) = true, want false")
	}
}

// TestSEC45ActionsSubsetAndContents proves SEC45Actions is the expected operator/SOAR
// state-mutating subset and that every entry is a privileged enum value.
func TestSEC45ActionsSubsetAndContents(t *testing.T) {
	t.Parallel()
	want := map[audit.Action]bool{
		audit.ActionRevokeOne:       true,
		audit.ActionRevokeAll:       true,
		audit.ActionEditDenylist:    true,
		audit.ActionOverrideQuota:   true,
		audit.ActionDestroy:         true,
		audit.ActionRetentionPolicy: true,
	}
	got := audit.SEC45Actions()
	if len(got) != len(want) {
		t.Fatalf("SEC45Actions() len = %d, want %d", len(got), len(want))
	}
	for _, a := range got {
		if !want[a] {
			t.Fatalf("SEC45Actions() contains unexpected action %v", a)
		}
		if !audit.IsPrivileged(a) {
			t.Fatalf("SEC45Actions() contains non-privileged action %v", a)
		}
	}
}

// TestSEC72ActionsLabelSet proves the SEC-72 label set carries the canon transitions
// with the deferred verbs forward-declared (HasEnum=false) and the enum-backed labels
// mapping onto privileged actions.
func TestSEC72ActionsLabelSet(t *testing.T) {
	t.Parallel()
	got := audit.SEC72Actions()
	if len(got) == 0 {
		t.Fatal("SEC72Actions() is empty")
	}
	sawDeferred := false
	sawEnum := false
	for _, m := range got {
		if m.Label == "" {
			t.Fatal("SEC72 entry has an empty label")
		}
		if m.HasEnum {
			sawEnum = true
			if !audit.IsPrivileged(m.Action) {
				t.Fatalf("SEC72 enum-backed label %q maps to non-privileged action %v", m.Label, m.Action)
			}
		} else {
			sawDeferred = true
		}
	}
	if !sawEnum {
		t.Fatal("SEC72Actions() has no enum-backed entry")
	}
	if !sawDeferred {
		t.Fatal("SEC72Actions() has no forward-declared deferred-verb entry")
	}
}

// TestSEC72EnumActionsDistinct proves SEC72EnumActions returns the distinct enum
// values the label set maps onto, with no duplicate and excluding deferred labels.
func TestSEC72EnumActionsDistinct(t *testing.T) {
	t.Parallel()
	got := audit.SEC72EnumActions()
	seen := make(map[audit.Action]bool, len(got))
	for _, a := range got {
		if seen[a] {
			t.Fatalf("SEC72EnumActions() has duplicate %v", a)
		}
		seen[a] = true
		if !audit.IsPrivileged(a) {
			t.Fatalf("SEC72EnumActions() contains non-privileged action %v", a)
		}
	}
	// The two enum-backed transitions create-commit and destroy must be present.
	if !seen[audit.ActionCreateCommit] {
		t.Fatal("SEC72EnumActions() missing ActionCreateCommit")
	}
	if !seen[audit.ActionDestroy] {
		t.Fatal("SEC72EnumActions() missing ActionDestroy")
	}
}

// TestFixtureVersion pins the versioned fixture stamp.
func TestFixtureVersion(t *testing.T) {
	t.Parallel()
	if audit.FixtureVersion != "v1" {
		t.Fatalf("FixtureVersion = %q, want v1", audit.FixtureVersion)
	}
}
