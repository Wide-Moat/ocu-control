// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
)

// TestRecordingFakeRecordsOnSuccess proves the success path: Emit records each
// Record in order and returns nil, so a flow's attested events are inspectable.
func TestRecordingFakeRecordsOnSuccess(t *testing.T) {
	t.Parallel()
	f := audit.NewRecordingFake()
	ctx := context.Background()

	want := []audit.Record{
		{Action: audit.ActionCreateCommit, Channel: "gateway", Key: "k1", Caller: "c1", Tenant: "t1"},
		{Action: audit.ActionDestroy, Channel: "gateway", Key: "k1", Caller: "c1", Tenant: "t1"},
		{Action: audit.ActionRevokeAll, Channel: "operator", Caller: "op", Tenant: "t1", Reason: "incident"},
	}
	for _, rec := range want {
		if err := f.Emit(ctx, rec); err != nil {
			t.Fatalf("Emit(%v): unexpected error %v", rec.Action, err)
		}
	}

	got := f.Records()
	if len(got) != len(want) {
		t.Fatalf("Records(): got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Records()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if f.Len() != len(want) {
		t.Fatalf("Len() = %d, want %d", f.Len(), len(want))
	}
}

// TestRecordingFakeFaultDeniesAndRecordsNothing is the fail-closed branch: with a
// fault armed, Emit returns a wrapped ErrAuditWriteFailed and records nothing, so
// the caller's deny branch runs and no event is attested for the denied action.
func TestRecordingFakeFaultDeniesAndRecordsNothing(t *testing.T) {
	t.Parallel()
	f := audit.NewRecordingFake()
	ctx := context.Background()

	cause := errors.New("disk full")
	f.SetFault(true, cause)

	err := f.Emit(ctx, audit.Record{Action: audit.ActionRevokeAll, Reason: "incident"})
	if err == nil {
		t.Fatalf("Emit with fault armed: got nil error, want failure")
	}
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Emit with fault armed: error %v does not match ErrAuditWriteFailed", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("Emit with fault armed: error %v does not wrap the cause %v", err, cause)
	}
	if f.Len() != 0 {
		t.Fatalf("Len() = %d after faulted Emit, want 0 (nothing recorded)", f.Len())
	}
}

// TestRecordingFakeFaultNilCauseStillWraps proves a nil cause still yields a
// meaningful wrapped sentinel, so the deny branch always sees ErrAuditWriteFailed.
func TestRecordingFakeFaultNilCauseStillWraps(t *testing.T) {
	t.Parallel()
	f := audit.NewRecordingFake()
	f.SetFault(true, nil)

	err := f.Emit(context.Background(), audit.Record{Action: audit.ActionDestroy})
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Emit with nil-cause fault: error %v does not match ErrAuditWriteFailed", err)
	}
}

// TestRecordingFakeDisarmRestoresSuccess proves SetFault(false, ...) restores the
// success path after a fault, so a test can model a transient outage then recovery.
func TestRecordingFakeDisarmRestoresSuccess(t *testing.T) {
	t.Parallel()
	f := audit.NewRecordingFake()
	ctx := context.Background()

	f.SetFault(true, nil)
	if err := f.Emit(ctx, audit.Record{Action: audit.ActionDestroy}); err == nil {
		t.Fatalf("Emit with fault armed: got nil error, want failure")
	}
	f.SetFault(false, nil)
	if err := f.Emit(ctx, audit.Record{Action: audit.ActionDestroy}); err != nil {
		t.Fatalf("Emit after disarm: unexpected error %v", err)
	}
	if f.Len() != 1 {
		t.Fatalf("Len() = %d after disarm-then-emit, want 1", f.Len())
	}
}

// TestRecordingFakeCancelledContextDenies proves Emit respects a cancelled
// context as a fail-closed deny, so a torn-down request cannot be reported as a
// durable record.
func TestRecordingFakeCancelledContextDenies(t *testing.T) {
	t.Parallel()
	f := audit.NewRecordingFake()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := f.Emit(ctx, audit.Record{Action: audit.ActionCreateCommit})
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Emit on cancelled ctx: error %v does not match ErrAuditWriteFailed", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Emit on cancelled ctx: error %v does not wrap context.Canceled", err)
	}
	if f.Len() != 0 {
		t.Fatalf("Len() = %d after cancelled Emit, want 0", f.Len())
	}
}

// TestActionString pins the closed-enum String mapping, including the
// out-of-range fail-visible label.
func TestActionString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a    audit.Action
		want string
	}{
		{audit.ActionCreateCommit, "create_commit"},
		{audit.ActionDestroy, "destroy"},
		{audit.ActionRevokeOne, "revoke_one"},
		{audit.ActionRevokeAll, "revoke_all"},
		{audit.ActionEditDenylist, "edit_denylist"},
		{audit.ActionOverrideQuota, "override_quota"},
		{audit.ActionRetentionPolicy, "retention_policy"},
		{audit.ActionCreateRejected, "create_rejected"},
		{audit.Action(250), "audit_action_unknown"},
	}
	for _, c := range cases {
		if got := c.a.String(); got != c.want {
			t.Fatalf("Action(%d).String() = %q, want %q", c.a, got, c.want)
		}
	}
}

// TestActionCreateRejectedStringAndPrivileged pins the new system-rejection arm: its
// String label is "create_rejected", it is an enumerated privileged Action, and the
// first value past it (lastAction+1) is NOT privileged — so the rejection arm closes
// the enum without admitting an unknown.
func TestActionCreateRejectedStringAndPrivileged(t *testing.T) {
	t.Parallel()
	if got := audit.ActionCreateRejected.String(); got != "create_rejected" {
		t.Fatalf("ActionCreateRejected.String() = %q, want create_rejected", got)
	}
	if !audit.IsPrivileged(audit.ActionCreateRejected) {
		t.Fatal("IsPrivileged(ActionCreateRejected) = false, want true")
	}
	// ActionCreateRejected is the new highest enum value; one past it is unknown.
	beyond := audit.Action(uint8(audit.ActionCreateRejected) + 1)
	if audit.IsPrivileged(beyond) {
		t.Fatalf("IsPrivileged(%d) = true, want false (one past the last enum arm)", beyond)
	}
}
