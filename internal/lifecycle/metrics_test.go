// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// recordingRecorder is a test lifecycle.Recorder: it counts the create/destroy
// increments and captures every observed start duration, so a test can assert the
// Manager recorded the lifecycle metrics on the success paths.
type recordingRecorder struct {
	creates           int
	destroys          int
	quotaRefundFailed int
	starts            []time.Duration
}

func (r *recordingRecorder) IncCreate()            { r.creates++ }
func (r *recordingRecorder) IncDestroy()           { r.destroys++ }
func (r *recordingRecorder) IncQuotaRefundFailed() { r.quotaRefundFailed++ }
func (r *recordingRecorder) ObserveStart(d time.Duration) {
	r.starts = append(r.starts, d)
}

// newManagerWithRecorder builds a Manager wired with rec as its metrics recorder
// over the recording provider, so a create/destroy drives the real pipeline.
func newManagerWithRecorder(t *testing.T, rec lifecycle.Recorder) *lifecycle.Manager {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := newListerStore(state.NewInMemory(clk))
	cust := registry.NewCustodian(store)
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())

	return lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      newRecordingProvider(),
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
		Metrics:       rec,
	})
}

// TestMetricsRecordedOnCreateAndDestroy proves the Manager records IncCreate +
// ObserveStart on a successful create and IncDestroy on a successful destroy, on
// the real pipeline. The start observation is what the admin avg-start-time tile
// derives from, so it must fire exactly once per create.
func TestMetricsRecordedOnCreateAndDestroy(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{}
	mgr := newManagerWithRecorder(t, rec)
	ctx := context.Background()

	if _, err := mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.creates != 1 {
		t.Errorf("IncCreate count after one create = %d; want 1", rec.creates)
	}
	if len(rec.starts) != 1 {
		t.Fatalf("ObserveStart count after one create = %d; want exactly 1 (the avg-start tile source)", len(rec.starts))
	}
	if rec.starts[0] < 0 {
		t.Errorf("observed start duration is negative (%v); a monotonic interval is never negative", rec.starts[0])
	}

	if err := mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if rec.destroys != 1 {
		t.Errorf("IncDestroy count after one destroy = %d; want 1", rec.destroys)
	}
}

// TestMetricsNilRecorderIsCleanNoOp proves the pipeline runs with a nil recorder —
// the metrics calls are guarded, so a deployment without an exporter is unaffected.
func TestMetricsNilRecorderIsCleanNoOp(t *testing.T) {
	t.Parallel()
	mgr := newManagerWithRecorder(t, nil)
	ctx := context.Background()
	if _, err := mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create with nil recorder: %v", err)
	}
	if err := mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy with nil recorder: %v", err)
	}
}

// newErrManagerWithRecorder builds a Manager over the fault-injecting errStore (so a
// concurrency release/refund can be armed to fail) AND a recording Recorder, so a test
// can assert the reclaim/reap paths fire IncQuotaRefundFailed on a release failure.
func newErrManagerWithRecorder(t *testing.T, rec lifecycle.Recorder) (*lifecycle.Manager, *errStore) {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := newListerStore(state.NewInMemory(clk))
	store := &errStore{listerStore: inner}
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      newRecordingProvider(),
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 100, CreateRatePerCallerPerMin: 100}),
		Handoff:       newFaultStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
		Metrics:       rec,
	})
	return mgr, store
}

// TestMetricsRecordedOnReclaimReleaseFailure proves the reclaim/reap concurrency-
// release-failure path fires IncQuotaRefundFailed, mirroring the create-unwind path
// (#188): a RESERVED row's slot refund fails (failChargeNeg) during Reconcile, so
// reclaimOrphanRow returns the error -- which would otherwise reach a loggerless daemon
// tick and be silent. The metric is the ONLY signal, so it must fire. A count of 0
// means the drift is invisible (the bug this closes); the emit-then-return is preserved
// (Reconcile still surfaces the injected fault).
func TestMetricsRecordedOnReclaimReleaseFailure(t *testing.T) {
	t.Parallel()
	rec := &recordingRecorder{}
	mgr, store := newErrManagerWithRecorder(t, rec)
	ctx := context.Background()

	stranded := state.Identity{Tenant: "tenant-r", Caller: "caller-r"}
	key := registry.DeriveKey(stranded, "stranded-reap")
	cust := registry.NewCustodian(store)
	if _, err := cust.Reserve(ctx, key, stranded); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}

	store.failChargeNeg = true // the reclaim's concurrency refund is a negative-delta Charge
	if err := mgr.Reconcile(ctx); !errors.Is(err, errLcInjected) {
		t.Fatalf("Reconcile with a failing reclaim refund = %v; want the injected fault", err)
	}
	if rec.quotaRefundFailed != 1 {
		t.Errorf("IncQuotaRefundFailed count on a reclaim release failure = %d; want 1 "+
			"(#188: the reap/reclaim drift must not be silent)", rec.quotaRefundFailed)
	}
}
