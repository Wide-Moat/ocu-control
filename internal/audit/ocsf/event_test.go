// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fixedStart is a deterministic instant the FakeClock starts at so the time fields
// are reproducible across runs.
var fixedStart = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// TestBuildEventMapsRecordFaithfully pins the OCSF mapping for a create-commit:
// class/category, the type_uid rule, the activity, the host-attested actor copied
// from the Record, the time from the injected Clock, and the unmapped action/reason.
func TestBuildEventMapsRecordFaithfully(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(fixedStart)
	rec := audit.Record{
		Action:  audit.ActionCreateCommit,
		Channel: "operator",
		Key:     "sess-key-1",
		Caller:  "op-caller",
		Tenant:  "tenant-9",
		Reason:  "scheduled",
	}

	ev := buildEvent(clk, rec)

	if ev.ClassUID != classUIDAPIActivity {
		t.Fatalf("class_uid = %d, want %d", ev.ClassUID, classUIDAPIActivity)
	}
	if ev.CategoryUID != categoryUIDApplicationActivity {
		t.Fatalf("category_uid = %d, want %d", ev.CategoryUID, categoryUIDApplicationActivity)
	}
	wantType := uint64(classUIDAPIActivity)*100 + uint64(activityCreate)
	if ev.TypeUID != wantType {
		t.Fatalf("type_uid = %d, want %d (class*100+activity)", ev.TypeUID, wantType)
	}
	if ev.ActivityID != activityCreate {
		t.Fatalf("activity_id = %d, want %d (Create)", ev.ActivityID, activityCreate)
	}
	if ev.ActivityName != "create_commit" {
		t.Fatalf("activity_name = %q, want create_commit", ev.ActivityName)
	}
	if ev.Time != fixedStart.UnixMilli() {
		t.Fatalf("time = %d, want %d (from injected clock)", ev.Time, fixedStart.UnixMilli())
	}
	if ev.TimeDT != fixedStart.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("time_dt = %q, want %q", ev.TimeDT, fixedStart.UTC().Format(time.RFC3339Nano))
	}
	if ev.StatusID != statusSuccess || ev.Status != "Success" {
		t.Fatalf("status = (%d,%q), want (%d,Success)", ev.StatusID, ev.Status, statusSuccess)
	}
	if ev.SeverityID != severityInformational {
		t.Fatalf("severity_id = %d, want %d (Informational)", ev.SeverityID, severityInformational)
	}
	if ev.Actor.User.Name != "op-caller" || ev.Actor.User.UIDAlt != "tenant-9" {
		t.Fatalf("actor.user = %+v, want {op-caller tenant-9}", ev.Actor.User)
	}
	if ev.Actor.Session.UID != "sess-key-1" {
		t.Fatalf("actor.session.uid = %q, want sess-key-1", ev.Actor.Session.UID)
	}
	if ev.Actor.InvokedBy != "operator" {
		t.Fatalf("actor.invoked_by = %q, want operator", ev.Actor.InvokedBy)
	}
	if ev.Metadata.Product.Name != productName || ev.Metadata.LogProvider != productName {
		t.Fatalf("metadata product/log_provider = (%q,%q), want %q", ev.Metadata.Product.Name, ev.Metadata.LogProvider, productName)
	}
	if ev.Metadata.Version != schemaVersion {
		t.Fatalf("metadata.version = %q, want %q", ev.Metadata.Version, schemaVersion)
	}
	if ev.Metadata.CorrelationUID != "sess-key-1" {
		t.Fatalf("metadata.correlation_uid = %q, want sess-key-1", ev.Metadata.CorrelationUID)
	}
	if ev.Metadata.Unmapped.Action != "create_commit" || ev.Metadata.Unmapped.Reason != "scheduled" {
		t.Fatalf("metadata.unmapped = %+v, want {create_commit scheduled}", ev.Metadata.Unmapped)
	}
}

// TestActivityForMapsEveryPrivilegedAction asserts the activity mapping is total
// over the privileged enum: create→Create, destroy→Delete, the operator controls→
// Update, and an out-of-range value→Other. No privileged action maps to Other.
func TestActivityForMapsEveryPrivilegedAction(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a    audit.Action
		want uint8
	}{
		{audit.ActionCreateCommit, activityCreate},
		{audit.ActionDestroy, activityDelete},
		{audit.ActionRevokeOne, activityUpdate},
		{audit.ActionRevokeAll, activityUpdate},
		{audit.ActionEditDenylist, activityUpdate},
		{audit.ActionOverrideQuota, activityUpdate},
		{audit.ActionRetentionPolicy, activityUpdate},
		{audit.ActionResumeGlobal, activityUpdate},
		{audit.ActionMCPKeyCreate, activityUpdate},
		{audit.ActionMCPKeyRevoke, activityUpdate},
		{audit.ActionCreateRejected, activityOther},
		{audit.Action(200), activityOther},
	}
	for _, c := range cases {
		got, name := activityFor(c.a)
		if got != c.want {
			t.Fatalf("activityFor(%v) = %d, want %d", c.a, got, c.want)
		}
		if name != c.a.String() {
			t.Fatalf("activityFor(%v) name = %q, want %q", c.a, name, c.a.String())
		}
	}
	// No privileged action falls to Other EXCEPT the create-rejected refusal, which
	// faithfully has no CRUD slot and maps to Other(99) by design. Excepting exactly
	// this one arm keeps the guard for any genuinely-forgotten arm.
	for _, a := range audit.PrivilegedActions() {
		if a == audit.ActionCreateRejected {
			continue
		}
		if id, _ := activityFor(a); id == activityOther {
			t.Fatalf("privileged action %v maps to Other(99) — every privileged action must map to a real activity", a)
		}
	}
}

// TestSeverityForRaisesRevokeAll proves the DENY-ALL revoke is raised to High while
// every other privileged action stays Informational.
func TestSeverityForRaisesRevokeAll(t *testing.T) {
	t.Parallel()
	if got := severityFor(audit.ActionRevokeAll); got != severityHigh {
		t.Fatalf("severityFor(RevokeAll) = %d, want %d (High)", got, severityHigh)
	}
	for _, a := range audit.PrivilegedActions() {
		if a == audit.ActionRevokeAll {
			continue
		}
		if got := severityFor(a); got != severityInformational {
			t.Fatalf("severityFor(%v) = %d, want %d (Informational)", a, got, severityInformational)
		}
	}
}

// TestStatusName covers the success and failure labels and the unknown fallback.
func TestStatusName(t *testing.T) {
	t.Parallel()
	if got := statusName(statusSuccess); got != "Success" {
		t.Fatalf("statusName(success) = %q, want Success", got)
	}
	if got := statusName(statusFailure); got != "Failure" {
		t.Fatalf("statusName(failure) = %q, want Failure", got)
	}
	if got := statusName(255); got != "Unknown" {
		t.Fatalf("statusName(255) = %q, want Unknown", got)
	}
}

// TestBuildEventRejectionHasFailureStatus pins the OCSF mapping for a system-initiated
// create rejection: the status is the honest Failure (NOT Success), the activity is
// Other(99) with the self-describing name, the type_uid follows the OCSF rule, the
// actor.user is the host-attested caller/tenant (non-blank), the severity is
// Informational, and the serialized JSON carries no token key.
func TestBuildEventRejectionHasFailureStatus(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(fixedStart)
	rec := audit.Record{
		Action:  audit.ActionCreateRejected,
		Channel: "operator",
		Key:     "k",
		Caller:  "op",
		Tenant:  "t9",
		Reason:  "admission-rejection",
	}

	ev := buildEvent(clk, rec)

	if ev.StatusID != statusFailure || ev.Status != "Failure" {
		t.Fatalf("status = (%d,%q), want (%d,Failure) — a rejection is NOT Success", ev.StatusID, ev.Status, statusFailure)
	}
	if ev.ActivityID != activityOther {
		t.Fatalf("activity_id = %d, want %d (Other) for a refusal with no CRUD slot", ev.ActivityID, activityOther)
	}
	if ev.ActivityName != "create_rejected" {
		t.Fatalf("activity_name = %q, want create_rejected", ev.ActivityName)
	}
	wantType := uint64(classUIDAPIActivity)*100 + uint64(activityOther)
	if ev.TypeUID != wantType {
		t.Fatalf("type_uid = %d, want %d (class*100+Other = 600399)", ev.TypeUID, wantType)
	}
	if ev.Actor.User.Name != "op" || ev.Actor.User.UIDAlt != "t9" {
		t.Fatalf("actor.user = %+v, want {op t9} (host-attested, non-blank)", ev.Actor.User)
	}
	if ev.Actor.InvokedBy != "operator" {
		t.Fatalf("actor.invoked_by = %q, want operator", ev.Actor.InvokedBy)
	}
	if ev.SeverityID != severityInformational {
		t.Fatalf("severity_id = %d, want %d (Informational) — a routine fail-closed outcome", ev.SeverityID, severityInformational)
	}
	// The serialized event still carries no credential key.
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	assertNoTokenKeys(t, generic)
}

// TestEventCarriesNoTokenField is the STRUCTURAL no-token guarantee: the serialized
// OCSF event JSON carries no auth_token / token / credential key, and the only string
// values present are the Record fields (none of which is a cred.Token). This is the
// structural half of the no-token-in-event invariant; the grep half lives in the
// sink test that runs a real create through a capturing writer.
func TestEventCarriesNoTokenField(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(fixedStart)
	ev := buildEvent(clk, audit.Record{
		Action: audit.ActionCreateCommit,
		Key:    "k", Caller: "c", Tenant: "t", Channel: "gateway", Reason: "r",
	})
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	assertNoTokenKeys(t, generic)
}

// assertNoTokenKeys recursively asserts no map key in the decoded event names a
// credential field.
func assertNoTokenKeys(t *testing.T, v any) {
	t.Helper()
	forbidden := map[string]bool{
		"auth_token": true, "token": true, "authorization": true,
		"bearer": true, "credential": true, "secret": true, "jwt": true,
	}
	switch m := v.(type) {
	case map[string]any:
		for k, child := range m {
			if forbidden[k] {
				t.Fatalf("OCSF event carries forbidden credential key %q", k)
			}
			assertNoTokenKeys(t, child)
		}
	case []any:
		for _, child := range m {
			assertNoTokenKeys(t, child)
		}
	}
}
