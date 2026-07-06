// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestQuotaRefundFailureIsObservable is the Finding #4 fix-(A) keystone. The unwind
// swallows every compensator error (the create already failed, the compensators are
// idempotent), so a quota refund that CANNOT apply — the exact create-abort leak that
// drifts the concurrency cell above the true live count — is otherwise silent: nothing
// records that a slot was leaked. That silence is why the drift was undiagnosable from
// outside (no log line, no metric, just an eventual opaque 409).
//
// The fix makes the failed refund observable: the quota-refund compensator increments
// a leaked-counter metric when Receipt.Apply fails. This drives a create to a
// post-charge failure (materialize) with the refund faulted, and asserts the metric
// fired. Drop the metric increment and the failure stays silent — this reds.
func TestQuotaRefundFailureIsObservable(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(lifeStart)
	inner := newListerStore(state.NewInMemory(clk))
	store := &errStore{listerStore: inner}
	store.failChargeNeg = true // the unwind refund is a negative-delta Charge
	provider := newRecordingProvider()
	provider.failMaterialize = true // fail AFTER the S3 charge so the unwind runs the refund
	rec := &recordingRecorder{}

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 100, CreateRatePerCallerPerMin: 100}),
		Handoff:       newFaultStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage}, // the mount-config leg gates create on the image allow-list; the test image must be allowed so the create reaches materialize
		ExecVerifyKey: pub32(),
		Metrics:       rec,
	})

	// The create fails at materialize; the unwind then runs the quota refund, which the
	// faulted store rejects. The create still returns the materialize error (the refund
	// failure is swallowed by the unwind, as before) — the observable side effect is the
	// metric.
	_, err := mgr.Create(context.Background(), input("refund-fault"))
	if !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("Create error = %v, want ErrMaterialize", err)
	}
	if rec.quotaRefundFailed != 1 {
		t.Fatalf("quota-refund-failed metric = %d, want 1 (a swallowed refund failure must be observable)", rec.quotaRefundFailed)
	}
}
