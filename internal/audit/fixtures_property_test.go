// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit_test

import (
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
)

// TestMCPKeyActionStrings pins the wire labels of the two new mcp-key operator
// actions. The labels are stable constants used in OCSF records; a rename of
// the String arm without updating this pin is a breaking wire change.
func TestMCPKeyActionStrings(t *testing.T) {
	t.Parallel()
	if got := audit.ActionMCPKeyCreate.String(); got != "mcp_key_create" {
		t.Fatalf("ActionMCPKeyCreate.String() = %q, want %q", got, "mcp_key_create")
	}
	if got := audit.ActionMCPKeyRevoke.String(); got != "mcp_key_revoke" {
		t.Fatalf("ActionMCPKeyRevoke.String() = %q, want %q", got, "mcp_key_revoke")
	}
}

// TestMCPKeyActionsArePrivileged confirms both new mcp-key arms are enumerated
// privileged actions — they fall within 0..lastAction and render a non-unknown
// String. An out-of-range value is never privileged; these must be.
func TestMCPKeyActionsArePrivileged(t *testing.T) {
	t.Parallel()
	for _, a := range []audit.Action{audit.ActionMCPKeyCreate, audit.ActionMCPKeyRevoke} {
		if !audit.IsPrivileged(a) {
			t.Fatalf("IsPrivileged(%v) = false, want true — action is not enumerated", a)
		}
		if a.String() == "audit_action_unknown" {
			t.Fatalf("action %v renders audit_action_unknown — String() arm is missing", a)
		}
	}
}

// TestMCPKeyActionsInSEC45 confirms both new mcp-key arms appear in SEC45Actions
// — they are operator/SOAR state-mutating actions (the SEC-45 family). A new
// privileged mcp-key action that is not in SEC45 would escape the audit wrap.
func TestMCPKeyActionsInSEC45(t *testing.T) {
	t.Parallel()
	sec45 := make(map[audit.Action]bool)
	for _, a := range audit.SEC45Actions() {
		sec45[a] = true
	}
	for _, a := range []audit.Action{audit.ActionMCPKeyCreate, audit.ActionMCPKeyRevoke} {
		if !sec45[a] {
			t.Fatalf("action %v is not in SEC45Actions — an mcp-key operator verb must be in the SEC-45 family", a)
		}
	}
}

// TestActionCreateRejectedIsStillLast confirms ActionCreateRejected remains the
// last enum arm (the lastAction boundary anchor) after the two mcp-key arms are
// inserted before it. The exhaustiveness walk (0..lastAction) and the one-past-
// the-end "audit_action_unknown" boundary depend on this ordering invariant.
func TestActionCreateRejectedIsStillLast(t *testing.T) {
	t.Parallel()
	actions := audit.PrivilegedActions()
	if len(actions) == 0 {
		t.Fatal("PrivilegedActions() is empty; something broke the walk")
	}
	last := actions[len(actions)-1]
	if last != audit.ActionCreateRejected {
		t.Fatalf("last PrivilegedActions() arm = %v (%q), want ActionCreateRejected — ActionCreateRejected must stay the boundary anchor", last, last.String())
	}
}

// TestPrivilegedActionsIncludesMCPKey confirms PrivilegedActions() now includes
// both mcp-key arms and that the total count has grown by two from the previous
// baseline (9 actions → 11 actions).
func TestPrivilegedActionsIncludesMCPKey(t *testing.T) {
	t.Parallel()
	const want = 12 // was 11; +ActionExec (the F10 tool-call family)
	got := audit.PrivilegedActions()
	if len(got) != want {
		t.Fatalf("PrivilegedActions() len = %d, want %d", len(got), want)
	}
	seen := make(map[audit.Action]bool)
	for _, a := range got {
		seen[a] = true
	}
	if !seen[audit.ActionMCPKeyCreate] {
		t.Fatal("PrivilegedActions() does not contain ActionMCPKeyCreate")
	}
	if !seen[audit.ActionMCPKeyRevoke] {
		t.Fatal("PrivilegedActions() does not contain ActionMCPKeyRevoke")
	}
}

// TestFixtureVersionBumped confirms the FixtureVersion was bumped from v1 to v2
// when the two mcp-key arms were added. A fixture-set change without a version bump
// would leave downstream consumers running the wrong revision.
func TestFixtureVersionBumped(t *testing.T) {
	t.Parallel()
	if audit.FixtureVersion != "v3" {
		t.Fatalf("FixtureVersion = %q, want v3 after the exec tool-call arm was added", audit.FixtureVersion)
	}
}
