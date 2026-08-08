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
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
	"github.com/Wide-Moat/ocu-control/internal/warmclaim"
)

// fakePool hands out a scripted set of warm units and records Get/Put so a test
// can assert a hit was claimed and a failed create returned or disposed it.
type fakePool struct {
	mu          sync.Mutex
	units       []warmclaim.Unit // popped FIFO on Get
	getCalls    int
	putCalls    int
	putUnits    []warmclaim.Unit
	lastProfile warmclaim.Profile // the profile Get was last queried with
}

func (p *fakePool) Get(prof warmclaim.Profile) (warmclaim.Unit, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.getCalls++
	p.lastProfile = prof
	if len(p.units) == 0 {
		return warmclaim.Unit{}, false
	}
	u := p.units[0]
	p.units = p.units[1:]
	return u, true
}

func (p *fakePool) Put(u warmclaim.Unit) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.putCalls++
	p.putUnits = append(p.putUnits, u)
}

// fakeClaimer records Claim/Dispose. Claim returns a scripted sandbox+material or
// a scripted error; Dispose counts the disposals so a leak (neither Put nor
// Dispose) is detectable.
type fakeClaimer struct {
	mu           sync.Mutex
	claimCalls   int
	disposeCalls int
	claimErr     error
	lastPubKey   []byte
	lastName     runtime.SessionName
	sandbox      runtime.Sandbox
	material     runtime.HandoffMaterial
}

func (c *fakeClaimer) Claim(_ context.Context, u warmclaim.Unit, realName runtime.SessionName, realPubKey []byte, _ runtime.EgressPolicy) (runtime.Sandbox, runtime.HandoffMaterial, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.claimCalls++
	c.lastPubKey = realPubKey
	c.lastName = realName
	if c.claimErr != nil {
		return runtime.Sandbox{}, runtime.HandoffMaterial{}, c.claimErr
	}
	sb := c.sandbox
	sb.Name = realName
	sb.RuntimeID = "ocu-sess-" + string(realName)
	sb.SockDirRoot = "/var/lib/ocu/handoff/" + u.PlaceholderID
	return sb, c.material, nil
}

func (c *fakeClaimer) Dispose(_ context.Context, _ warmclaim.Unit) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disposeCalls++
	return nil
}

func newWarmHarness(t *testing.T, pool warmclaim.Pool, claimer warmclaim.Claimer) *harness {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := newListerStore(state.NewInMemory(clk))
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
		Pool:          pool,
		Claimer:       claimer,
	})
	return &harness{mgr: mgr, store: store, provider: provider, stager: stager, audit: sink, gate: gate, clk: clk}
}

func warmUnit(id string) warmclaim.Unit {
	// The unit carries a placeholder Staged handoff (a Root the compensator would
	// reclaim); the fake claimer never inspects Material, only PlaceholderID.
	return warmclaim.Unit{PlaceholderID: id, Handoff: stagedFor(id)}
}

// TestWarmHit_ClaimsInsteadOfMaterialize is the keystone: a warm hit runs Claim
// with the REAL exec verify key (not the placeholder), sets the row's container
// name from the claimed sandbox, and NEVER calls the cold provider.Materialize.
func TestWarmHit_ClaimsInsteadOfMaterialize(t *testing.T) {
	t.Parallel()
	pool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-1")}}
	claimer := &fakeClaimer{}
	h := newWarmHarness(t, pool, claimer)

	row, err := h.mgr.Create(context.Background(), input("warm-sess"))
	if err != nil {
		t.Fatalf("Create (warm hit): %v", err)
	}

	if claimer.claimCalls != 1 {
		t.Errorf("Claim called %d times, want 1", claimer.claimCalls)
	}
	if h.provider.materializeCalls != 0 {
		t.Errorf("cold provider.Materialize called %d times on a warm hit, want 0", h.provider.materializeCalls)
	}
	// Claim received the DEPLOYMENT exec verify key, not a per-session/placeholder key.
	if !bytesEqual(claimer.lastPubKey, pub32()) {
		t.Error("Claim did not receive the deployment exec verify key")
	}
	// The row carries the claimed container name and the warm sock-dir root.
	if row.ContainerName != "ocu-sess-"+row.Key {
		t.Errorf("row.ContainerName = %q, want the claimed container name", row.ContainerName)
	}
	if row.SockDirRoot == "" {
		t.Error("row.SockDirRoot is empty on a warm hit; the finalizer would miss the pooled root")
	}
}

// TestWarmHit_ProfileCarriesTheCreateCaps binds warmProfile: the pool is queried
// with a Profile whose image and hard caps (CPU, memory, and the dereferenced
// PidsLimit) come from the CreateInput, so a pooled unit is matched to the caps the
// caller asked for rather than a default shape. It exercises warmProfile's
// PidsLimit-non-nil arm, which the nil-pids inputs elsewhere never reach.
func TestWarmHit_ProfileCarriesTheCreateCaps(t *testing.T) {
	t.Parallel()
	pool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-caps")}}
	h := newWarmHarness(t, pool, &fakeClaimer{})

	in := input("warm-caps")
	pids := int64(4096)
	in.Resources.PidsLimit = &pids
	in.Resources.CPUCores = 2
	in.Resources.MemoryBytes = 2 << 30

	if _, err := h.mgr.Create(context.Background(), in); err != nil {
		t.Fatalf("Create (warm caps): %v", err)
	}
	got := pool.lastProfile
	if got.ImageRef != in.Image {
		t.Errorf("profile ImageRef = %q, want %q", got.ImageRef, in.Image)
	}
	if got.CPUCores != in.Resources.CPUCores {
		t.Errorf("profile CPUCores = %v, want %v", got.CPUCores, in.Resources.CPUCores)
	}
	if got.MemoryBytes != in.Resources.MemoryBytes {
		t.Errorf("profile MemoryBytes = %d, want %d", got.MemoryBytes, in.Resources.MemoryBytes)
	}
	// The dereferenced PidsLimit is the arm the nil-pids inputs never reach.
	if got.PidsLimit != pids {
		t.Errorf("profile PidsLimit = %d, want %d (dereferenced from the non-nil cap)", got.PidsLimit, pids)
	}
}

// TestWarmMiss_FallsThroughToCold pins that an empty pool (miss) runs the cold
// path unchanged: provider.Materialize is called, Claim is not.
func TestWarmMiss_FallsThroughToCold(t *testing.T) {
	t.Parallel()
	pool := &fakePool{} // empty: every Get misses
	claimer := &fakeClaimer{}
	h := newWarmHarness(t, pool, claimer)

	if _, err := h.mgr.Create(context.Background(), input("cold-sess")); err != nil {
		t.Fatalf("Create (warm miss): %v", err)
	}
	if claimer.claimCalls != 0 {
		t.Errorf("Claim called on a pool miss (%d); want the cold path", claimer.claimCalls)
	}
	if h.provider.materializeCalls != 1 {
		t.Errorf("cold Materialize called %d times on a miss, want 1", h.provider.materializeCalls)
	}
}

// TestWarmHit_ClaimFailureDisposesUnitAndFailsCreate is the no-leak keystone:
// when Claim fails, the unit is disposed (not leaked, not returned to the pool)
// and the create fails.
func TestWarmHit_ClaimFailureDisposesUnitAndFailsCreate(t *testing.T) {
	t.Parallel()
	pool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-2")}}
	claimer := &fakeClaimer{claimErr: errors.New("claim refused")}
	h := newWarmHarness(t, pool, claimer)

	if _, err := h.mgr.Create(context.Background(), input("fail-sess")); err == nil {
		t.Fatal("Create with a failing Claim returned nil; want the claim error")
	}
	// The unit was DISPOSED (Branch B: claim-attempted), never Put back to the pool
	// (a claim-attempted unit is renamed/started and unreturnable — NFR-SEC-68).
	if claimer.disposeCalls == 0 {
		t.Error("a failed Claim did not dispose the unit — it leaks")
	}
	if pool.putCalls != 0 {
		t.Errorf("a claim-attempted unit was returned to the pool (%d Puts); it must be disposed, not returned", pool.putCalls)
	}
}

// TestWarmHit_ClaimSucceedsThenCommitFailsForceKillsAndDisposes covers the
// stageMaterialize warm-success teardown compensator: a warm claim that SUCCEEDS
// (S8) and then hits a later failure (here the S9 commit audit-emit faults) must
// unwind cleanly — the started sandbox is force-killed by the S8 compensator and
// the claim-attempted unit is disposed by the S5 Branch-B compensator, so a
// commit-time failure leaks neither a running container nor a pooled handoff root.
func TestWarmHit_ClaimSucceedsThenCommitFailsForceKillsAndDisposes(t *testing.T) {
	t.Parallel()
	pool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-commitfail")}}
	claimer := &fakeClaimer{}
	h := newWarmHarness(t, pool, claimer)
	// Fault the commit audit record: Claim already ran and succeeded, so the unwind
	// starts from S9 and must reverse the successful S8 claim.
	h.audit.SetFault(true, errors.New("commit emit refused"))

	if _, err := h.mgr.Create(context.Background(), input("commitfail-sess")); err == nil {
		t.Fatal("Create with a faulting commit returned nil; want the audit deny")
	}
	// The claim SUCCEEDED, so its teardown compensator must have force-killed the
	// started sandbox (the S8 warm-success compensator, the covered arm).
	if h.provider.forceKillCalls == 0 {
		t.Error("a warm claim that succeeded then failed at commit did not force-kill the started sandbox — it leaks a running container")
	}
	// And the claim-attempted unit is disposed, never returned (Branch B).
	if claimer.disposeCalls == 0 {
		t.Error("the claim-attempted unit was not disposed on the commit-fail unwind — it leaks the pooled handoff root")
	}
	if pool.putCalls != 0 {
		t.Errorf("a claim-attempted unit was returned to the pool (%d Puts) on a commit-fail unwind; it must be disposed", pool.putCalls)
	}
}

// TestWarmHit_UnwindAfterHitReturnsPristineUnit pins Branch A: when the create
// fails AFTER the warm handoff hit but BEFORE stageMaterialize claims (here, a
// forced commit failure would be ideal, but we drive it via a quota-refund path);
// the pristine unit is RETURNED to the pool, not disposed. We approximate the
// pre-claim unwind by making the claimer's Claim itself the first failure is
// Branch B; to exercise Branch A we need a failure between S5 and S8. The
// audit-commit fault store gives us exactly that.
func TestWarmHit_UnwindBeforeClaimReturnsPristineUnit(t *testing.T) {
	t.Parallel()
	pool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-3")}}
	claimer := &fakeClaimer{}
	// A store whose Commit fails: the create unwinds from S9 (commit), so S8's
	// Claim already ran — that is Branch B, not A. To hit Branch A we fail at S6/S7.
	// The simplest S6/S7 failure with a warm hit is a mint failure: no Signer wired
	// means the mint stage is a clean no-op, so instead we use a claimer whose
	// Claim is never reached because we fail earlier. Drive a render/push failure.
	h := newWarmHarnessWithPushFault(t, pool, claimer)

	if _, err := h.mgr.Create(context.Background(), input("pristine-sess")); err == nil {
		t.Fatal("Create with a push fault returned nil; want the injected fault")
	}
	// The unit was never claimed (the failure is before S8), so it is PRISTINE and
	// RETURNED to the pool, not disposed.
	if claimer.claimCalls != 0 {
		t.Errorf("Claim ran (%d) before the pre-S8 failure; the unit should be pristine", claimer.claimCalls)
	}
	if pool.putCalls != 1 {
		t.Errorf("a pristine unit was not returned to the pool (%d Puts); Branch A must Put", pool.putCalls)
	}
	if claimer.disposeCalls != 0 {
		t.Errorf("a pristine unit was disposed (%d) instead of returned", claimer.disposeCalls)
	}
}

// stagedFor builds a minimal placeholder Staged for a fake pool unit — a Root the
// Branch-B compensator would reclaim. The fake claimer never reads Material.
func stagedFor(id string) handoff.Staged {
	return handoff.Staged{Root: "/var/lib/ocu/handoff/" + id}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// newWarmHarnessWithPushFault wires a Signer + a push-faulting Pusher so the
// storage render/push stage (S7) fails AFTER the warm handoff hit (S5) but BEFORE
// the claim (S8) — exercising Branch A of the warm compensator (pristine return).
func newWarmHarnessWithPushFault(t *testing.T, pool warmclaim.Pool, claimer warmclaim.Claimer) *harness {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := newListerStore(state.NewInMemory(clk))
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())
	signer, _ := newTestSigner(t, clk)
	pusher := newRecordingPusher()
	pusher.failPush = true
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
		Signer:        signer,
		Push:          pusher,
		ServiceURL:    testServiceURL,
		CACertPEM:     testCACert,
		MountDefaults: testMountDefaults(t),
		StorageScope:  lifecycle.StorageScope{Workspace: "ws", Org: "org", Intent: cred.IntentWrite},
		Pool:          pool,
		Claimer:       claimer,
	})
	return &harness{mgr: mgr, store: store, provider: provider, stager: stager, audit: sink, gate: gate, clk: clk}
}

// TestWarmHit_CommitRecordMarksThePoolClaim pins NFR-SEC-72: a warm-pool-served
// create's commit audit record carries WarmHit=true, and a cold create's does
// not, so the pool-claim lifecycle transition is distinguishable on the
// tamper-evident spine.
func TestWarmHit_CommitRecordMarksThePoolClaim(t *testing.T) {
	t.Parallel()

	// Warm hit: the commit record is marked.
	warmPool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-audit")}}
	hw := newWarmHarness(t, warmPool, &fakeClaimer{})
	if _, err := hw.mgr.Create(context.Background(), input("warm-audit")); err != nil {
		t.Fatalf("Create (warm): %v", err)
	}
	if !hasWarmHitCommit(hw.audit.Records(), true) {
		t.Error("a warm-pool create's commit record is not marked WarmHit=true (the pool-claim transition is invisible on the spine)")
	}

	// Cold create (empty pool): the commit record is NOT marked.
	coldPool := &fakePool{}
	hc := newWarmHarness(t, coldPool, &fakeClaimer{})
	if _, err := hc.mgr.Create(context.Background(), input("cold-audit")); err != nil {
		t.Fatalf("Create (cold): %v", err)
	}
	if hasWarmHitCommit(hc.audit.Records(), true) {
		t.Error("a cold create's commit record is marked WarmHit=true; the marker must distinguish a pool claim from a cold materialize")
	}
}

func hasWarmHitCommit(recs []audit.Record, want bool) bool {
	for _, r := range recs {
		if r.Action == audit.ActionCreateCommit && r.WarmHit == want {
			return true
		}
	}
	return false
}

// TestWarmHit_DestroyDialsTheWarmSockDir covers sockDirFor's warm branch: a
// destroy of a warm-claimed session (row.SockDirRoot set) resolves the advisory
// control-RPC sock dir via SockDirUnder(root), targeting the pooled root — NOT
// the name-derived base/<key> a cold session uses.
func TestWarmHit_DestroyDialsTheWarmSockDir(t *testing.T) {
	t.Parallel()
	pool := &fakePool{units: []warmclaim.Unit{warmUnit("pool-destroy")}}
	claimer := &fakeClaimer{}
	dialer, h := newWarmHarnessWithDialer(t, pool, claimer)

	row, err := h.mgr.Create(context.Background(), input("warm-destroy"))
	if err != nil {
		t.Fatalf("Create (warm): %v", err)
	}
	// The claimed row carries the warm root the fake claimer minted; the destroy
	// dial must resolve its sock dir UNDER that root, not the name-derived base.
	if row.SockDirRoot == "" {
		t.Fatal("warm create left SockDirRoot empty; the destroy branch cannot be exercised")
	}
	wantSockDir := h.stager.SockDirUnder(row.SockDirRoot)

	if err := h.mgr.Destroy(context.Background(), testCaller, "warm-destroy"); err != nil {
		t.Fatalf("Destroy of a warm session: %v", err)
	}
	// The advisory dial ran and targeted the warm root's sock dir — proving
	// sockDirFor took the warm branch (SockDirUnder(root)) rather than the
	// name-derived SockDir(key) a cold session would use.
	if dialer.calls == 0 {
		t.Fatal("the destroy advisory dial never ran for a warm session")
	}
	if dialer.lastSockDir != wantSockDir {
		t.Errorf("destroy dialed sockDir %q, want the warm root's sock dir %q", dialer.lastSockDir, wantSockDir)
	}
}

// newWarmHarnessWithDialer builds the warm harness with a recording control
// dialer wired, so a warm session's Destroy exercises the advisory dial (and thus
// sockDirFor's warm branch).
func newWarmHarnessWithDialer(t *testing.T, pool warmclaim.Pool, claimer warmclaim.Claimer) (*recordingDialer, *harness) {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	store := newListerStore(state.NewInMemory(clk))
	provider := newRecordingProvider()
	stager := newFaultStager(t.TempDir())
	sink := audit.NewRecordingFake()
	gate := quota.NewGate(store, clk, generousLimits())
	dialer := newRecordingDialer(provider)
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         gate,
		Handoff:       stager,
		Audit:         sink,
		Profile:       admission.ProfileTrustedOperator,
		Tier:          runtime.TierRunc,
		AllowedImages: []string{testGuestImage},
		ExecVerifyKey: pub32(),
		ControlDialer: dialer,
		Pool:          pool,
		Claimer:       claimer,
	})
	return dialer, &harness{mgr: mgr, store: store, provider: provider, stager: stager, audit: sink, gate: gate, clk: clk}
}
