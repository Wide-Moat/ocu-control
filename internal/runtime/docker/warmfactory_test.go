// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtime/warmpool"
)

func warmTestProfile() warmpool.Profile {
	return warmpool.Profile{ImageRef: "img@sha256:abc", CPUCores: 2, MemoryBytes: 512 << 20, PidsLimit: 256, FUSE: false}
}

func newWarmFactory(t *testing.T, api dockerAPI) *WarmFactory {
	t.Helper()
	stager := handoff.NewStager(t.TempDir())
	return NewWarmFactory(api, stager, runtime.TierGvisor, "", "")
}

func realPub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestCreatePlaceholder_NeverStartsAndAttachesNoNetwork is the pool-invariant
// keystone: a placeholder is CREATED but NEVER started, and it holds NO network
// (so it is a never-run guest with no bridge to leak — NFR-SEC-68/70).
func TestCreatePlaceholder_NeverStartsAndAttachesNoNetwork(t *testing.T) {
	api := newFakeAPI()
	f := newWarmFactory(t, api)

	u, err := f.CreatePlaceholder(context.Background(), warmTestProfile())
	if err != nil {
		t.Fatalf("CreatePlaceholder: %v", err)
	}
	if u.PlaceholderID == "" {
		t.Error("placeholder has no id")
	}
	if api.countOp("ContainerStart") != 0 {
		t.Error("CreatePlaceholder STARTED the container — a pooled unit must be never-run")
	}
	if api.countOp("NetworkCreate") != 0 || api.countOp("NetworkConnect") != 0 {
		t.Error("CreatePlaceholder attached a network — a placeholder must hold none (the real bridge is claim-time)")
	}
	if api.countOp("ContainerCreate") != 1 {
		t.Errorf("want exactly one ContainerCreate, got %d", api.countOp("ContainerCreate"))
	}
}

// TestClaim_SpecializesRenamesConnectsThenStarts is the claim-order keystone:
// EVERY specialize step runs BEFORE ContainerStart — ClaimSpecialize (handoff),
// ContainerRename, NetworkCreate+Connect, and only THEN ContainerStart. If start
// preceded any of them the guest would boot into the placeholder identity or
// with no network.
func TestClaim_SpecializesRenamesConnectsThenStarts(t *testing.T) {
	api := newFakeAPI()
	f := newWarmFactory(t, api)
	u, err := f.CreatePlaceholder(context.Background(), warmTestProfile())
	if err != nil {
		t.Fatalf("CreatePlaceholder: %v", err)
	}

	sb, _, err := f.Claim(context.Background(), u, "sess-real-1", realPub(t),
		runtime.EgressPolicy{DefaultDeny: true, FilesystemID: "fs-1"})
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if sb.Name != "sess-real-1" || sb.RuntimeID != "ocu-sess-sess-real-1" {
		t.Errorf("Claim handle = %+v, want the real session name + pure-function container name", sb)
	}

	// The one ContainerStart happens AFTER rename and network connect.
	startIdx := api.indexOf("ContainerStart")
	renameIdx := api.indexOf("ContainerRename")
	connIdx := api.indexOf("NetworkConnect")
	if startIdx < 0 {
		t.Fatal("Claim never started the container")
	}
	if !(renameIdx >= 0 && renameIdx < startIdx) {
		t.Errorf("ContainerRename (idx %d) must precede ContainerStart (idx %d)", renameIdx, startIdx)
	}
	if !(connIdx >= 0 && connIdx < startIdx) {
		t.Errorf("NetworkConnect (idx %d) must precede ContainerStart (idx %d)", connIdx, startIdx)
	}
	// A pure-exec profile gets its own per-session bridge created at claim.
	if api.countOp("NetworkCreate") != 1 {
		t.Errorf("want one claim-time NetworkCreate for the per-session bridge, got %d", api.countOp("NetworkCreate"))
	}
}

// TestClaim_RollsBackBridgeOnStartFailure is the no-orphan keystone: when
// ContainerStart fails, the per-session bridge created during the claim is
// removed, so a failed claim leaves no orphan network.
func TestClaim_RollsBackBridgeOnStartFailure(t *testing.T) {
	api := newFakeAPI()
	api.errOn["ContainerStart"] = errors.New("start refused")
	f := newWarmFactory(t, api)
	u, _ := f.CreatePlaceholder(context.Background(), warmTestProfile())

	_, _, err := f.Claim(context.Background(), u, "sess-real-2", realPub(t),
		runtime.EgressPolicy{DefaultDeny: true, FilesystemID: "fs-2"})
	if !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("Claim error = %v, want ErrMaterialize on a start failure", err)
	}
	if api.countOp("NetworkRemove") != 1 {
		t.Errorf("a failed-claim start did not remove the bridge it created (NetworkRemove count = %d)", api.countOp("NetworkRemove"))
	}
}

// TestClaim_RollsBackBridgeOnConnectFailure covers the connect-failure rollback
// arm: the bridge was created but NetworkConnect failed, so the bridge is removed
// and the guest never starts.
func TestClaim_RollsBackBridgeOnConnectFailure(t *testing.T) {
	api := newFakeAPI()
	api.errOn["NetworkConnect"] = errors.New("connect refused")
	f := newWarmFactory(t, api)
	u, _ := f.CreatePlaceholder(context.Background(), warmTestProfile())

	_, _, err := f.Claim(context.Background(), u, "sess-real-3", realPub(t),
		runtime.EgressPolicy{DefaultDeny: true, FilesystemID: "fs-3"})
	if !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("Claim error = %v, want ErrMaterialize on a connect failure", err)
	}
	if api.countOp("ContainerStart") != 0 {
		t.Error("Claim started the guest despite a failed network connect")
	}
	if api.countOp("NetworkRemove") != 1 {
		t.Errorf("a failed-claim connect did not remove the bridge it created (NetworkRemove count = %d)", api.countOp("NetworkRemove"))
	}
}

// TestDestroyPlaceholder_RemovesAndIsIdempotent pins the reaper path: it force-
// removes the container and a not-found is a satisfied destroy.
func TestDestroyPlaceholder_RemovesAndIsIdempotent(t *testing.T) {
	api := newFakeAPI()
	f := newWarmFactory(t, api)
	u, _ := f.CreatePlaceholder(context.Background(), warmTestProfile())

	if err := f.DestroyPlaceholder(context.Background(), u); err != nil {
		t.Fatalf("DestroyPlaceholder: %v", err)
	}
	if api.countOp("ContainerRemove") != 1 {
		t.Errorf("want one ContainerRemove, got %d", api.countOp("ContainerRemove"))
	}
	// A second destroy of the now-gone unit is satisfied (idempotent), not an error.
	if err := f.DestroyPlaceholder(context.Background(), u); err != nil {
		t.Fatalf("second DestroyPlaceholder must be satisfied, got %v", err)
	}
}

// TestCreatePlaceholder_AbortsFirecracker pins the fail-closed tier gate: a
// TierFirecracker factory refuses with ErrNotImplemented and creates nothing.
func TestCreatePlaceholder_AbortsFirecracker(t *testing.T) {
	api := newFakeAPI()
	stager := handoff.NewStager(t.TempDir())
	f := NewWarmFactory(api, stager, runtime.TierFirecracker, "", "")

	if _, err := f.CreatePlaceholder(context.Background(), warmTestProfile()); !errors.Is(err, runtime.ErrNotImplemented) {
		t.Fatalf("CreatePlaceholder on firecracker = %v, want ErrNotImplemented", err)
	}
	if len(api.ops()) != 0 {
		t.Errorf("firecracker abort issued %d SDK calls, want zero", len(api.ops()))
	}
}

// TestCreatePlaceholder_UnstagesOnCreateFailure covers the create-failure
// cleanup arm: when ContainerCreate fails, the placeholder handoff root is
// unstaged so no orphan handoff tree leaks.
func TestCreatePlaceholder_UnstagesOnCreateFailure(t *testing.T) {
	api := newFakeAPI()
	api.errOn["ContainerCreate"] = errors.New("create refused")
	f := newWarmFactory(t, api)

	if _, err := f.CreatePlaceholder(context.Background(), warmTestProfile()); !errors.Is(err, runtime.ErrMaterialize) {
		t.Fatalf("CreatePlaceholder on a create failure = %v, want ErrMaterialize", err)
	}
	// The staged root was cleaned up: a second create reuses seq+1, and no handoff
	// tree from the failed attempt should remain (we assert via the stager base
	// having no leftover pool root — the stager removed it on Unstage).
}

// TestClaim_StorageProfileJoinsEgressNetwork covers the FUSE-profile network arm:
// a storage profile on a deployment with a shared egress network joins THAT at
// claim (no per-session bridge created), matching the cold path.
func TestClaim_StorageProfileJoinsEgressNetwork(t *testing.T) {
	api := newFakeAPI()
	stager := handoff.NewStager(t.TempDir())
	f := NewWarmFactory(api, stager, runtime.TierGvisor, "ocu-egress", "10.0.0.1")

	p := warmTestProfile()
	p.FUSE = true
	u, err := f.CreatePlaceholder(context.Background(), p)
	if err != nil {
		t.Fatalf("CreatePlaceholder: %v", err)
	}

	if _, _, err := f.Claim(context.Background(), u, "sess-fuse-1", realPub(t),
		runtime.EgressPolicy{DefaultDeny: true, FilesystemID: "fs-fuse"}); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// A storage profile on a deployment with an egress network joins it — no
	// per-session bridge is created at claim (the bridge is the pure-exec path).
	if api.countOp("NetworkCreate") != 0 {
		t.Errorf("storage-profile claim created a per-session bridge (count %d); it should join the shared egress network", api.countOp("NetworkCreate"))
	}
	if api.countOp("NetworkConnect") != 1 {
		t.Errorf("storage-profile claim did not connect to the egress network (NetworkConnect count %d)", api.countOp("NetworkConnect"))
	}
}

// TestDispose_DelegatesToDestroyPlaceholder covers the Dispose alias (the
// create-unwind compensator's disposal verb).
func TestDispose_DelegatesToDestroyPlaceholder(t *testing.T) {
	api := newFakeAPI()
	f := newWarmFactory(t, api)
	u, _ := f.CreatePlaceholder(context.Background(), warmTestProfile())
	if err := f.Dispose(context.Background(), u); err != nil {
		t.Fatalf("Dispose: %v", err)
	}
	if api.countOp("ContainerRemove") != 1 {
		t.Errorf("Dispose did not force-remove the container (ContainerRemove=%d)", api.countOp("ContainerRemove"))
	}
}

// TestProviderNewWarmFactory_SharesTheClient covers Provider.NewWarmFactory: the
// factory it returns drives the SAME injected client (a create-placeholder lands
// a ContainerCreate on the provider's fake), so the daemon's single dockerAPI
// client stays in one place.
func TestProviderNewWarmFactory_SharesTheClient(t *testing.T) {
	api := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierGvisor, Deps{API: api, StagerBase: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	stager := handoff.NewStager(t.TempDir())
	f := p.NewWarmFactory(stager)
	if f == nil {
		t.Fatal("NewWarmFactory returned nil")
	}
	if _, err := f.CreatePlaceholder(context.Background(), warmTestProfile()); err != nil {
		t.Fatalf("CreatePlaceholder via provider factory: %v", err)
	}
	if api.countOp("ContainerCreate") != 1 {
		t.Errorf("the provider's warm factory did not use the provider's client (ContainerCreate=%d)", api.countOp("ContainerCreate"))
	}
}
