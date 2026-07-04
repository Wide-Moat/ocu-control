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
	return newHarnessWithExec(t, nil)
}

// newHarnessWithExec builds the same harness as newHarness but wires an exec
// driver through ManagerDeps. A nil driver yields the plain harness (Exec then
// fail-closes), so newHarness delegates here.
func newHarnessWithExec(t *testing.T, execDriver lifecycle.ExecDriver) *harness {
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
		Custodian:     cust,
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		ExecDriver:    execDriver,
		ExecVerifyKey: pub32(),
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
		Caller:      testCaller,
		SessionHint: hint,
		Image:       "registry.example/ocu-sandbox:v1",
		Mount:       runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", ReadOnly: false, CacheSeconds: 5},
		Egress:      runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-1"},
		Resources:   runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
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
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, generousLimits()),
		Handoff:       newFaultStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       admission.ProfileUntrusted, // untrusted × runc = pairing-rejected
		Tier:          runtime.TierRunc,
		ExecVerifyKey: pub32(),
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
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, quota.Limits{ConcurrentSessionsPerTenant: 1, CreateRatePerCallerPerMin: 100}),
		Handoff:       newFaultStager(t.TempDir()),
		Audit:         audit.NewRecordingFake(),
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		ExecVerifyKey: pub32(),
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

// rejectHarness bundles a Manager plus the fakes the create-rejection audit tests
// inspect. It is built with a caller-chosen profile/tier and quota limits so each of
// the three deny stages (admission, quota, kill-switch) can be driven in turn.
type rejectHarness struct {
	mgr      *lifecycle.Manager
	store    *listerStore
	provider *recordingProvider
	audit    *audit.RecordingFake
}

// newRejectHarness builds a Manager over an in-mem Store, a recording provider, and
// the audit recording fake at the given profile/tier and quota limits.
func newRejectHarness(t *testing.T, profile admission.WorkloadProfile, tier runtime.RuntimeTier, limits quota.Limits) *rejectHarness {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	sink := audit.NewRecordingFake()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, limits),
		Handoff:       newFaultStager(t.TempDir()),
		Audit:         sink,
		Profile:       profile,
		Tier:          tier,
		ExecVerifyKey: pub32(),
	})
	return &rejectHarness{mgr: mgr, store: store, provider: provider, audit: sink}
}

// onlyRejection returns the single ActionCreateRejected record the sink holds,
// failing the test if there is not exactly one and asserting no create_commit record
// leaked.
func onlyRejection(t *testing.T, sink *audit.RecordingFake) audit.Record {
	t.Helper()
	recs := sink.Records()
	if len(recs) != 1 {
		t.Fatalf("audit records = %+v, want exactly one create_rejected", recs)
	}
	if recs[0].Action != audit.ActionCreateRejected {
		t.Fatalf("audit record action = %v, want ActionCreateRejected", recs[0].Action)
	}
	if recs[0].Caller != testCaller.Identity.Caller || recs[0].Tenant != testCaller.Identity.Tenant {
		t.Fatalf("audit identity = %q/%q, want host-attested %q/%q",
			recs[0].Caller, recs[0].Tenant, testCaller.Identity.Caller, testCaller.Identity.Tenant)
	}
	if recs[0].Channel != testCaller.Channel.String() {
		t.Fatalf("audit channel = %q, want %q", recs[0].Channel, testCaller.Channel.String())
	}
	if recs[0].Key == "" {
		t.Fatal("audit record Key is blank; want the host-derived correlation key")
	}
	return recs[0]
}

// TestCreateAdmissionRejectedEmitsAudit proves the S2 deny emits exactly one
// system-initiated create-rejection record carrying the host-attested identity and
// the admission-rejection cause, BEFORE the typed admission error propagates, and
// touches no substrate.
func TestCreateAdmissionRejectedEmitsAudit(t *testing.T) {
	t.Parallel()
	h := newRejectHarness(t, admission.ProfileUntrusted, runtime.TierRunc, generousLimits())

	_, err := h.mgr.Create(context.Background(), input("x"))
	if !errors.Is(err, admission.ErrAdmissionRejected) {
		t.Fatalf("Create error = %v, want ErrAdmissionRejected", err)
	}
	rec := onlyRejection(t, h.audit)
	if rec.Reason != "admission-rejection" {
		t.Fatalf("rejection Reason = %q, want admission-rejection", rec.Reason)
	}
	if h.provider.materializeCalls != 0 {
		t.Fatalf("Materialize called %d times on an admission-rejected create; want 0", h.provider.materializeCalls)
	}
}

// TestCreateQuotaRejectedEmitsAudit proves the S3 deny emits exactly one
// system-initiated create-rejection record with the quota-rejection cause, leaves the
// concurrent counter at the one live session, and writes no second commit record.
func TestCreateQuotaRejectedEmitsAudit(t *testing.T) {
	t.Parallel()
	h := newRejectHarness(t, admission.ProfileTrustedOperator, runtime.TierRunc,
		quota.Limits{ConcurrentSessionsPerTenant: 1, CreateRatePerCallerPerMin: 100})
	ctx := context.Background()

	if _, err := h.mgr.Create(ctx, input("first")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// The first create's commit record is present; clear the sink so the rejection is
	// the only record under assertion.
	if h.audit.Len() != 1 || h.audit.Records()[0].Action != audit.ActionCreateCommit {
		t.Fatalf("after first create, audit = %+v, want one create_commit", h.audit.Records())
	}

	_, err := h.mgr.Create(ctx, input("second"))
	if !errors.Is(err, state.ErrQuotaExceeded) {
		t.Fatalf("second Create error = %v, want ErrQuotaExceeded", err)
	}
	recs := h.audit.Records()
	if len(recs) != 2 || recs[1].Action != audit.ActionCreateRejected || recs[1].Reason != "quota-rejection" {
		t.Fatalf("audit = %+v, want create_commit then create_rejected(quota-rejection)", recs)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 1 {
		t.Fatalf("concurrent counter after quota rejection = %d, want 1 (the one live session)", got)
	}
}

// TestCreateKillSwitchRejectedEmitsAudit proves the S4 deny-posture re-check emits
// exactly one create-rejection record with the killswitch-rejection cause for BOTH
// the global kill-switch (ErrKillSwitchEngaged) and a per-key denylist
// (ErrSessionDenied), and leaves no ACTIVE row and the concurrent counter back at 0
// (the S3 receipt refunded on unwind, proving no side-effect).
func TestCreateKillSwitchRejectedEmitsAudit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Variant 1: global DENY-ALL.
	h := newRejectHarness(t, admission.ProfileTrustedOperator, runtime.TierRunc, generousLimits())
	if err := h.store.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal}); err != nil {
		t.Fatalf("SetDeny global: %v", err)
	}
	_, err := h.mgr.Create(ctx, input("denied-global"))
	if !errors.Is(err, state.ErrKillSwitchEngaged) {
		t.Fatalf("Create under DENY-ALL error = %v, want ErrKillSwitchEngaged", err)
	}
	rec := onlyRejection(t, h.audit)
	if rec.Reason != "killswitch-rejection" {
		t.Fatalf("global-deny rejection Reason = %q, want killswitch-rejection", rec.Reason)
	}
	if got := concurrentCount(t, h.store, testCaller.Identity); got != 0 {
		t.Fatalf("concurrent counter after global-deny rejection = %d, want 0 (refunded on unwind)", got)
	}

	// Variant 2: per-key denylist. Create then destroy a session to learn its
	// host-derived key (mintHandle is host-internal), denylist that exact key, then
	// re-create with the SAME hint, which derives the SAME key and is refused at S4.
	h2 := newRejectHarness(t, admission.ProfileTrustedOperator, runtime.TierRunc, generousLimits())
	row, err := h2.mgr.Create(ctx, input("denied-key"))
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	if err := h2.mgr.Destroy(ctx, testCaller, "denied-key"); err != nil {
		t.Fatalf("seed Destroy: %v", err)
	}
	if err := h2.store.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: row.Key}); err != nil {
		t.Fatalf("SetDeny session: %v", err)
	}
	beforeLen := h2.audit.Len() // create_commit + destroy already recorded
	_, err = h2.mgr.Create(ctx, input("denied-key"))
	if !errors.Is(err, state.ErrSessionDenied) {
		t.Fatalf("Create under per-key denylist error = %v, want ErrSessionDenied", err)
	}
	recs := h2.audit.Records()
	if len(recs) != beforeLen+1 {
		t.Fatalf("audit recorded %d records after per-key denial, want %d (+1 rejection)", len(recs), beforeLen+1)
	}
	last := recs[len(recs)-1]
	if last.Action != audit.ActionCreateRejected || last.Reason != "killswitch-rejection" {
		t.Fatalf("last audit record = %+v, want create_rejected(killswitch-rejection)", last)
	}
	if got := concurrentCount(t, h2.store, testCaller.Identity); got != 0 {
		t.Fatalf("concurrent counter after per-key rejection = %d, want 0 (refunded on unwind)", got)
	}
}

// TestRejectionAuditPrecedesDeny is the ordering assertion: on success the rejection
// Record is durable in the sink at the instant the typed error returns (synchronous
// emit), and on a faulted sink RecordingFake records nothing, so no half-written
// rejection record exists; in both cases no substrate side-effect occurs.
func TestRejectionAuditPrecedesDeny(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Success-emit: the rejection record is present the moment the deny returns.
	h := newRejectHarness(t, admission.ProfileUntrusted, runtime.TierRunc, generousLimits())
	_, err := h.mgr.Create(ctx, input("ordering-ok"))
	if !errors.Is(err, admission.ErrAdmissionRejected) {
		t.Fatalf("Create error = %v, want ErrAdmissionRejected", err)
	}
	if h.audit.Len() != 1 {
		t.Fatalf("rejection record count at deny = %d, want 1 (durable before the deny returned)", h.audit.Len())
	}
	if h.provider.materializeCalls != 0 {
		t.Fatalf("Materialize called %d times; a deny must touch no substrate", h.provider.materializeCalls)
	}

	// Audit-failure: the faulted sink records nothing, so no half-written record exists.
	hf := newRejectHarness(t, admission.ProfileUntrusted, runtime.TierRunc, generousLimits())
	hf.audit.SetFault(true, errors.New("sink down"))
	_, err = hf.mgr.Create(ctx, input("ordering-fault"))
	if !errors.Is(err, audit.ErrAuditWriteFailed) {
		t.Fatalf("Create on faulted sink error = %v, want ErrAuditWriteFailed", err)
	}
	if hf.audit.Len() != 0 {
		t.Fatalf("faulted-sink record count = %d, want 0 (no half-written rejection)", hf.audit.Len())
	}
	if hf.provider.materializeCalls != 0 {
		t.Fatalf("Materialize called %d times on a faulted-sink deny; want 0", hf.provider.materializeCalls)
	}
}
