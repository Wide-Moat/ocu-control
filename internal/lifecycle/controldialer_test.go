// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// errDialInjected is the typed fault recordingDialer returns when armed, so a test
// proves a failed advisory dial is swallowed and never aborts the finalizer.
var errDialInjected = errors.New("fakes: injected control-rpc dial fault")

// recordingDialer is a fake lifecycle.ControlDialer. It records every Shutdown
// call's sockDir and containerName, captures how many GracefulStop calls the
// finalizer had made AT the moment of the dial (so a test can prove the dial ran
// BEFORE the authoritative teardown), and can be armed to FAIL so the swallow path
// is exercised.
type recordingDialer struct {
	mu sync.Mutex
	// provider lets the dialer read the finalizer's GracefulStop count at dial time,
	// to prove the advisory dial precedes the authoritative teardown.
	provider *recordingProvider

	calls         int
	lastSockDir   string
	lastContainer string
	stopsAtDial   int // GracefulStop count observed when the dial ran
	fail          bool
}

func newRecordingDialer(p *recordingProvider) *recordingDialer {
	return &recordingDialer{provider: p}
}

func (d *recordingDialer) Shutdown(ctx context.Context, sockDir, containerName string) error {
	d.mu.Lock()
	d.calls++
	d.lastSockDir = sockDir
	d.lastContainer = containerName
	d.stopsAtDial = d.provider.gracefulStops()
	fail := d.fail
	d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if fail {
		return errDialInjected
	}
	return nil
}

func (d *recordingDialer) snapshot() (calls, stopsAtDial int, sockDir, container string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.stopsAtDial, d.lastSockDir, d.lastContainer
}

// newManagerWithDialer builds a Manager over the dialer's recording provider plus
// fresh fakes, mirroring newHarness but injecting the advisory ControlDialer. It
// returns the Manager and the store/audit fakes a destroy assertion inspects.
func newManagerWithDialer(t *testing.T, dialer *recordingDialer) (*lifecycle.Manager, *listerStore, *audit.RecordingFake) {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := newListerStore(state.NewInMemory(clk))
	cust := registry.NewCustodian(store)
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     cust,
		Provider:      dialer.provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		ControlDialer: dialer,
	})
	return mgr, store, sink
}

// TestDestroyDialsControlRPCBeforeFinalizerOnHappyPath proves the advisory dial
// runs BEFORE the authoritative GracefulStop on a clean destroy, that it targets
// the host-attested container name (never a body hint) and a non-empty re-derived
// sock dir, and that the finalizer still ran (the container is gone).
func TestDestroyDialsControlRPCBeforeFinalizerOnHappyPath(t *testing.T) {
	t.Parallel()
	dialer := newRecordingDialer(newRecordingProvider())
	mgr, _, _ := newManagerWithDialer(t, dialer)
	ctx := context.Background()

	row, err := mgr.Create(ctx, input("sess"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	calls, stopsAtDial, sockDir, container := dialer.snapshot()
	if calls != 1 {
		t.Fatalf("control-rpc Shutdown calls = %d, want exactly 1", calls)
	}
	// The dial ran BEFORE the finalizer's GracefulStop: zero stops had been made when
	// the advisory nudge fired.
	if stopsAtDial != 0 {
		t.Fatalf("GracefulStop count observed at dial = %d, want 0 (dial precedes finalizer)", stopsAtDial)
	}
	// The dial binds the per-dial exec JWT to the host-attested container name, never
	// a body hint.
	if container != row.ContainerName {
		t.Fatalf("dial container_name = %q, want host-attested %q", container, row.ContainerName)
	}
	// The sock dir is re-derived purely from the host-derived session key (the stager
	// layout base/<name>/sock); a non-empty path proves the re-derivation ran.
	if sockDir == "" {
		t.Fatal("dial sockDir empty; the sock dir must be re-derived from the session key")
	}
	// The authoritative finalizer still ran: no live container remains and exactly one
	// GracefulStop fired AFTER the dial.
	if got := dialer.provider.liveCount(); got != 0 {
		t.Fatalf("provider live after destroy = %d, want 0 (finalizer authoritative)", got)
	}
	if got := dialer.provider.gracefulStops(); got != 1 {
		t.Fatalf("GracefulStop calls = %d, want exactly 1 (finalizer ran after dial)", got)
	}
}

// TestDestroyContinuesToFinalizerWhenDialFails proves the advisory dial is
// best-effort: a failed Shutdown is swallowed and Destroy STILL runs the
// authoritative finalizer, releasing the row and freeing the container. The dial
// can never reorder or substitute the host-driven teardown (NFR-SEC-65/-01).
func TestDestroyContinuesToFinalizerWhenDialFails(t *testing.T) {
	t.Parallel()
	dialer := newRecordingDialer(newRecordingProvider())
	dialer.fail = true
	mgr, store, sink := newManagerWithDialer(t, dialer)
	ctx := context.Background()

	if _, err := mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := concurrentCount(t, store, testCaller.Identity); got != 1 {
		t.Fatalf("concurrent counter after create = %d, want 1", got)
	}

	// Destroy must succeed despite the dial fault: the dial error is non-authoritative.
	if err := mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy returned %v; a failed advisory dial must not fail teardown", err)
	}

	calls, _, _, _ := dialer.snapshot()
	if calls != 1 {
		t.Fatalf("control-rpc Shutdown calls = %d, want exactly 1 (attempted then swallowed)", calls)
	}
	// The authoritative finalizer still ran in full despite the dial failure.
	if got := dialer.provider.liveCount(); got != 0 {
		t.Fatalf("provider live after failed-dial destroy = %d, want 0 (finalizer ran anyway)", got)
	}
	if got := dialer.provider.gracefulStops(); got != 1 {
		t.Fatalf("GracefulStop calls = %d, want exactly 1 (finalizer ran after swallowed dial)", got)
	}
	if got := concurrentCount(t, store, testCaller.Identity); got != 0 {
		t.Fatalf("concurrent counter after destroy = %d, want 0 (released despite dial failure)", got)
	}
	recs := sink.Records()
	if len(recs) != 2 || recs[1].Action != audit.ActionDestroy {
		t.Fatalf("audit records = %+v, want create_commit then destroy", recs)
	}
}

// TestDestroyWithNilDialerIsCleanNoOp proves the Phase-3 minimal shelf (no
// ControlDialer wired) destroys cleanly: the advisory nudge is simply skipped and
// the authoritative finalizer runs unchanged.
func TestDestroyWithNilDialerIsCleanNoOp(t *testing.T) {
	t.Parallel()
	// newHarness wires NO ControlDialer (nil), the minimal-shelf posture.
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := h.mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy with nil dialer: %v", err)
	}
	if got := h.provider.liveCount(); got != 0 {
		t.Fatalf("provider live after nil-dialer destroy = %d, want 0", got)
	}
}
