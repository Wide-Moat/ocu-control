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
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// lifeStart anchors the FakeClock so the per-minute create-rate window label is
// reproducible across runs.
var lifeStart = time.Date(2025, time.March, 4, 5, 6, 7, 0, time.UTC)

// testCaller is the host-derived caller every test create runs under (the operator
// channel admits trusted_operator on runc/gVisor).
var testCaller = ingress.AuthenticatedCaller{
	Identity: state.Identity{Tenant: "tenant-a", Caller: "caller-1"},
	Channel:  ingress.ChannelGateway,
}

// pub32 is a 32-byte Ed25519-shaped public key the handoff stages without complaint.
func pub32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// generousLimits admits many creates so the quota gate is not the thing under test
// unless a test deliberately tightens it.
func generousLimits() quota.Limits {
	return quota.Limits{
		ConcurrentSessionsPerTenant: 100,
		CreateRatePerCallerPerMin:   100,
	}
}

// harness bundles the Manager and the fakes a test inspects after a flow.
type harness struct {
	mgr      *lifecycle.Manager
	store    *listerStore
	provider *recordingProvider
	stager   *faultStager
	audit    *audit.RecordingFake
	gate     *quota.Gate
	clk      *state.FakeClock
}

// newHarness builds a Manager over an in-mem Store (wrapped to enumerate live rows),
// a recording provider, a real-filesystem stager rooted at a temp dir, the audit
// recording fake, and a generous quota gate at the trusted_operator×runc admit cell.
func newHarness(t *testing.T) *harness {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	cust := registry.NewCustodian(store)
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: cust,
		Provider:  provider,
		Clock:     clk,
		Quota:     gate,
		Handoff:   stager,
		Audit:     sink,
		Profile:   admission.ProfileTrustedOperator,
		Tier:      runtime.TierRunc,
	})
	return &harness{
		mgr:      mgr,
		store:    store,
		provider: provider,
		stager:   stager,
		audit:    sink,
		gate:     gate,
		clk:      clk,
	}
}

// input builds a CreateInput with a 32-byte key under the test caller.
func input(hint string) lifecycle.CreateInput {
	return lifecycle.CreateInput{
		Caller:        testCaller,
		SessionHint:   hint,
		Image:         "registry.example/ocu-sandbox:v1",
		Mount:         runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", ReadOnly: false, CacheSeconds: 5},
		Egress:        runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-1"},
		Resources:     runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
		ControlPubKey: pub32(),
	}
}

// TestCreateHappyPathBindsActiveRow proves a clean create runs all eight stages and
// returns an ACTIVE, container-bound row, with a single create-commit audit record
// and exactly one live container.
func TestCreateHappyPathBindsActiveRow(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	row, err := h.mgr.Create(context.Background(), input("my-session"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("row state = %v, want ACTIVE", row.State)
	}
	if row.ContainerName == "" {
		t.Fatal("row.ContainerName empty; bind stage did not record the runtime id")
	}
	if got := h.provider.liveCount(); got != 1 {
		t.Fatalf("provider live containers = %d, want 1", got)
	}
	recs := h.audit.Records()
	if len(recs) != 1 || recs[0].Action != audit.ActionCreateCommit {
		t.Fatalf("audit records = %+v, want exactly one create_commit", recs)
	}
	if recs[0].Tenant != "tenant-a" || recs[0].Caller != "caller-1" {
		t.Fatalf("audit identity = %q/%q, want host-derived tenant-a/caller-1", recs[0].Tenant, recs[0].Caller)
	}
}

// TestCreateThenDestroyReleasesAndDecrements proves Destroy tears down a created
// session: it emits a destroy record, force-frees the container, releases the row,
// and returns the per-tenant concurrent slot so the level counter falls to zero.
func TestCreateThenDestroyReleasesAndDecrements(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.mgr.Create(ctx, input("sess")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 1 {
		t.Fatalf("concurrent counter after create = %d, want 1", got)
	}

	if err := h.mgr.Destroy(ctx, testCaller, "sess"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := h.provider.liveCount(); got != 0 {
		t.Fatalf("provider live after destroy = %d, want 0", got)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 0 {
		t.Fatalf("concurrent counter after destroy = %d, want 0", got)
	}
	recs := h.audit.Records()
	if len(recs) != 2 || recs[1].Action != audit.ActionDestroy {
		t.Fatalf("audit records = %+v, want create_commit then destroy", recs)
	}
}

// TestDestroyForeignHintNotOwned proves a caller cannot destroy another caller's
// session by presenting its hint: the foreign caller derives a key in its OWN
// namespace, so the lookup returns ErrNotOwned (indistinguishable from not-found)
// and the victim is never torn down.
func TestDestroyForeignHintNotOwned(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.mgr.Create(ctx, input("victim-session")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	attacker := ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "tenant-b", Caller: "caller-2"},
		Channel:  ingress.ChannelGateway,
	}
	err := h.mgr.Destroy(ctx, attacker, "victim-session")
	if !errors.Is(err, registry.ErrNotOwned) {
		t.Fatalf("foreign Destroy error = %v, want ErrNotOwned", err)
	}
	// The victim's container is untouched.
	if got := h.provider.liveCount(); got != 1 {
		t.Fatalf("victim container live count = %d, want 1 (untouched)", got)
	}
}

// TestCreateAuditFailureOnCommitDeniesAndUnwinds proves the audit fail-closed branch
// on the single privileged create checkpoint: with the sink faulted, the commit
// stage denies the create and the LIFO unwind leaves no row, no counter, no
// container, and no sockdir.
func TestCreateAuditFailureOnCommitDeniesAndUnwinds(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	h.audit.SetFault(true, errors.New("sink down"))

	_, err := h.mgr.Create(ctx, input("denied"))
	if err == nil {
		t.Fatal("Create succeeded with a faulted audit sink; want a fail-closed deny")
	}
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Create error = %v, want wrapped ErrAuditWriteFailed", err)
	}

	// No residue: no live container, no live concurrent counter, no audit record, no
	// staged sockdir.
	if got := h.provider.liveCount(); got != 0 {
		t.Fatalf("live containers after denied create = %d, want 0 (force-killed on unwind)", got)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 0 {
		t.Fatalf("concurrent counter after denied create = %d, want 0 (refunded on unwind)", got)
	}
	if h.audit.Len() != 0 {
		t.Fatalf("audit recorded %d events for a denied create, want 0", h.audit.Len())
	}
	if stageCalls, unstageCalls := h.stager.counts(); stageCalls != unstageCalls {
		t.Fatalf("stager stage=%d unstage=%d; every staged root must be unstaged on unwind", stageCalls, unstageCalls)
	}
}

// TestCreateUnattestedIdentityRejected proves the S1 fail-closed backstop: an empty
// host identity is rejected before any host state, with no row, counter, or
// container.
func TestCreateUnattestedIdentityRejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	in := input("x")
	in.Caller = ingress.AuthenticatedCaller{Channel: ingress.ChannelGateway} // empty Identity
	_, err := h.mgr.Create(context.Background(), in)
	if !errors.Is(err, lifecycle.ErrUnattested) {
		t.Fatalf("Create with empty identity error = %v, want ErrUnattested", err)
	}
	if got := h.provider.liveCount(); got != 0 {
		t.Fatalf("live containers after unattested create = %d, want 0", got)
	}
}

// TestCreateAdmissionRejected proves the S2 fail-closed reject runs before any host
// state: a deployment configured untrusted×runc refuses every create with the typed
// admission error and touches nothing.
func TestCreateAdmissionRejected(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: registry.NewCustodian(store),
		Provider:  provider,
		Clock:     clk,
		Quota:     quota.NewGate(store, clk, generousLimits()),
		Handoff:   newFaultStager(t.TempDir()),
		Audit:     audit.NewRecordingFake(),
		Profile:   admission.ProfileUntrusted, // untrusted × runc = pairing-rejected
		Tier:      runtime.TierRunc,
	})

	_, err := mgr.Create(context.Background(), input("x"))
	if !errors.Is(err, admission.ErrAdmissionRejected) {
		t.Fatalf("Create on rejected pairing error = %v, want ErrAdmissionRejected", err)
	}
	var re admission.RejectedError
	if !errors.As(err, &re) || re.Reason != admission.ReasonPairingRejected {
		t.Fatalf("Create rejection reason = %v, want ReasonPairingRejected", err)
	}
	if got := provider.liveCount(); got != 0 {
		t.Fatalf("live containers after rejected create = %d, want 0", got)
	}
	if provider.materializeCalls != 0 {
		t.Fatalf("Materialize called %d times on a rejected create; admission must run before any substrate call", provider.materializeCalls)
	}
}

// TestCreateQuotaRefusedNoCounter proves the S3 refused-not-queued path: a tightened
// concurrent limit refuses the second create with ErrQuotaExceeded and leaves the
// counter unchanged (the rate counter from the refused attempt is refunded by the
// gate).
func TestCreateQuotaRefusedNoCounter(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: registry.NewCustodian(store),
		Provider:  provider,
		Clock:     clk,
		Quota:     quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 1, CreateRatePerCallerPerMin: 100}),
		Handoff:   newFaultStager(t.TempDir()),
		Audit:     audit.NewRecordingFake(),
		Profile:   admission.ProfileTrustedOperator,
		Tier:      runtime.TierRunc,
	})
	ctx := context.Background()

	if _, err := mgr.Create(ctx, input("first")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := mgr.Create(ctx, input("second"))
	if !errors.Is(err, state.ErrQuotaExceeded) {
		t.Fatalf("second Create error = %v, want ErrQuotaExceeded", err)
	}
	if got := concurrentCount(t, store, testCaller.Identity); got != 1 {
		t.Fatalf("concurrent counter after refused create = %d, want 1 (the one live session)", got)
	}
}

// TestReconcileForceKillsOrphansAndReclaimsReserved proves the boot sweep:
// provider.Reconcile orphans are force-killed, and a crashed RESERVED row is
// Released AND its concurrent slot returned, so a crashed-mid-create row leaves no
// level-counter leak.
func TestReconcileForceKillsOrphansAndReclaimsReserved(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	// Stage a substrate orphan the provider still holds.
	h.provider.reconcileOrphans = []runtime.Sandbox{{Name: "orphan-1", RuntimeID: "ctr-orphan"}}

	// Simulate a crashed-mid-create RESERVED row: reserve through the Custodian path by
	// charging a concurrent slot and reserving the row directly via a create that we
	// stop short of commit. The cleanest in-test way is to drive a create that fails at
	// commit, but Create unwinds its own row. Instead, reserve a row out-of-band via a
	// fresh Custodian and charge the matching concurrent slot, modelling the durable
	// residue a crash leaves.
	stranded := state.Identity{Tenant: "tenant-c", Caller: "caller-3"}
	key := registry.DeriveKey(stranded, "stranded-handle")
	cust := registry.NewCustodian(h.store)
	if _, err := cust.Reserve(ctx, key, stranded); err != nil {
		t.Fatalf("seed reserve: %v", err)
	}
	// Charge the concurrent slot the crashed create would have charged.
	if _, err := h.store.Charge(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: stranded}, 1, 100); err != nil {
		t.Fatalf("seed charge: %v", err)
	}
	if got := concurrentCount(t, h.store, stranded); got != 1 {
		t.Fatalf("seeded concurrent counter = %d, want 1", got)
	}

	if err := h.mgr.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if h.provider.forceKillCalls != 1 {
		t.Fatalf("Reconcile force-killed %d orphans, want 1", h.provider.forceKillCalls)
	}
	if got := concurrentCount(t, h.store, stranded); got != 0 {
		t.Fatalf("stranded concurrent counter after reconcile = %d, want 0 (reclaimed)", got)
	}
	row, err := h.store.LookupSession(ctx, key.String())
	if err != nil {
		t.Fatalf("LookupSession after reconcile: %v", err)
	}
	if row.State != state.StateReleased {
		t.Fatalf("reclaimed row state = %v, want RELEASED", row.State)
	}
}

// concurrentCount reads the per-tenant concurrent-session level counter directly.
func concurrentCount(t *testing.T, store state.Store, id state.Identity) int64 {
	t.Helper()
	v, err := store.ReadQuota(context.Background(), state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: id})
	if err != nil {
		t.Fatalf("ReadQuota(concurrent): %v", err)
	}
	return v
}
