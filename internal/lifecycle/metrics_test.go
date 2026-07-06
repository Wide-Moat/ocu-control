// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
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
