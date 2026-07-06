// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"os"
	"path/filepath"
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
)

// TestCreateNoStorageScopeSucceeds is the ADR-0017 correctness proof: a pure
// compute/exec session that requests NO storage scope (a zero MountIntent — both
// FilesystemID and MemoryStoreID empty) is a legitimate first-class create and MUST
// succeed. The Manager is wired exactly like the shipped compose — a REAL cred.Signer
// and a real Push (recordingPusher) plus the deployment-fixed StorageScope — so the
// mint and render+push stages actually fire instead of no-opping. Because there is no
// storage scope to mint, those storage stages should be skipped, not run.
//
// On the unmodified phase-7 tree this create FAILS CLOSED at the mint stage with
// cred.ErrMintScope ("empty filesystem_id"), wrongly coupling the exec lifecycle to
// the storage leg. That failure is the RED proof for the skip fix.
func TestCreateNoStorageScopeSucceeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	sink := audit.NewRecordingFake()

	// Wire the storage leg as the shipped compose does: a real signer mints the weak
	// Storage-JWT and a real Push lands the rendered config on the host-owned bind, so
	// the mint and render+push stages are live (a nil Signer/Push would no-op them and
	// the no-scope coupling would be invisible).
	signer, _ := newTestSigner(t, clk)
	pusher := newRecordingPusher()

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, generousLimits()),
		Handoff:       handoff.NewStager(t.TempDir()),
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
	})

	// A pure compute/exec create: the Mount is the zero MountIntent — NO storage scope
	// requested (both FilesystemID and MemoryStoreID empty), and the Egress carries no
	// FilesystemID either.
	in := lifecycle.CreateInput{
		Caller:      testCaller,
		SessionHint: "no-scope-session",
		Image:       testGuestImage,
		Mount:       runtime.MountIntent{},
		Egress:      runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store"},
		Resources:   runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
	}

	row, err := mgr.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create with no storage scope (zero MountIntent) = %v; want success — a pure compute/exec session legitimately mints no Storage-JWT (ADR-0017)", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("no-scope created row state = %v, want ACTIVE", row.State)
	}
	if row.ContainerName == "" {
		t.Fatal("no-scope created row has no bound container_name; the create did not run to bind")
	}
	if got := provider.liveCount(); got != 1 {
		t.Fatalf("provider live containers = %d, want 1 (the sandbox materialized)", got)
	}

	// No storage scope means no Storage-JWT mint and nothing rendered/pushed onto the
	// bind: the storage stages were skipped, not run.
	if push, _ := pusher.counts(); push != 0 {
		t.Fatalf("Push called %d times on a no-scope create, want 0 (no mount-config to render/push)", push)
	}
	// And the materialized spec carries NO mount-config guest path: nothing was
	// pushed, so the provider's storage-scoped boot-child posture must not flip
	// (both-or-neither with the host render).
	if got := provider.materializedSpec().Handoff.MountConfigGuestPath; got != "" {
		t.Fatalf("no-scope spec.Handoff.MountConfigGuestPath = %q, want empty", got)
	}

	// The durable row is ACTIVE.
	got, err := store.LookupSession(ctx, row.Key)
	if err != nil {
		t.Fatalf("durable lookup of the no-scope row: %v", err)
	}
	if got.State != state.StateActive {
		t.Fatalf("durable no-scope row state = %v, want ACTIVE", got.State)
	}
}

// TestCreateStorageScopeDeliversMountConfig is the storage-scoped mirror of the
// no-scope proof above and the lifecycle half of the delivery keystone: a create
// that DOES request a storage scope must land the rendered mount-config INSIDE
// the per-session sock dir (the one handoff directory the provider binds RW into
// the guest — the handoff root itself is never bound) and hand the provider the
// matching IN-GUEST path on spec.Handoff.MountConfigGuestPath, so the provider
// flips the boot-child posture. Both-or-neither with the push.
func TestCreateStorageScopeDeliversMountConfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	sink := audit.NewRecordingFake()

	signer, _ := newTestSigner(t, clk)
	pusher := newRecordingPusher()

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     registry.NewCustodian(store),
		Provider:      provider,
		Clock:         clk,
		Quota:         quota.NewGate(store, clk, generousLimits()),
		Handoff:       handoff.NewStager(t.TempDir()),
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
	})

	in := lifecycle.CreateInput{
		Caller:      testCaller,
		SessionHint: "storage-session",
		Image:       testGuestImage,
		Mount:       runtime.MountIntent{Destination: "/workspace", FilesystemID: "fs-1", CacheSeconds: 5},
		Egress:      runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-1"},
		Resources:   runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
	}

	row, err := mgr.Create(ctx, in)
	if err != nil {
		t.Fatalf("storage-scoped Create: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("storage-scoped row state = %v, want ACTIVE", row.State)
	}

	// Exactly one push, landed INSIDE the sock dir — the bound directory — not on
	// the unbound handoff root.
	if push, _ := pusher.counts(); push != 1 {
		t.Fatalf("Push called %d times on a storage-scoped create, want 1", push)
	}
	hostPath := pusher.pushedPath()
	if hostPath == "" {
		t.Fatal("no pushed path recorded on a storage-scoped create")
	}
	if got := filepath.Base(filepath.Dir(hostPath)); got != "sock" {
		t.Fatalf("mount-config landed in %q (dir %q), want inside the per-session sock dir — the only handoff directory bound into the guest", hostPath, got)
	}
	// The file is physically present for the guest to read after the create.
	if _, err := os.Stat(hostPath); err != nil {
		t.Fatalf("pushed mount-config not on disk after a successful create: %v", err)
	}

	// The provider received the IN-GUEST path (the sock-dir mountpoint + fixed
	// name), never the host path.
	if got := provider.materializedSpec().Handoff.MountConfigGuestPath; got != "/run/ocu/mount-config.json" {
		t.Fatalf("spec.Handoff.MountConfigGuestPath = %q, want /run/ocu/mount-config.json", got)
	}
}
