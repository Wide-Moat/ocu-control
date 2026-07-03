// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// requireBindImage gates the LIVE control-path bind(2) e2e: it requires
// OCU_RUNTIME_IT_IMAGE to name a guest that actually binds its exec UDS under the
// provider's hardcoded --listen-uds Cmd (the sandbox guest exec-server). The default
// busybox image has no UDS-bind entrypoint, so the hardcoded Cmd would not bind a
// socket and the bind-proof would be vacuous; rather than fake-green against
// busybox, the e2e skips cleanly there and runs only where a bind-capable guest
// image is supplied. This mirrors requireIT/requireRunsc: the skip names the
// requirement so a green CI is never mistaken for an executed bind assertion.
func requireBindImage(t *testing.T) string {
	t.Helper()
	img := os.Getenv("OCU_RUNTIME_IT_IMAGE")
	if img == "" || img == defaultITImage {
		t.Skipf("bind e2e: set OCU_RUNTIME_IT_IMAGE to a guest image that binds the "+
			"exec UDS under the provider Cmd (the sandbox guest exec-server); the default %q has no "+
			"UDS-bind entrypoint so the bind-proof would be vacuous — skipping", defaultITImage)
	}
	return img
}

// bindSpec stages the per-session handoff via the REAL handoff.Stager so the sock
// dir carries the exact production posture under test (the 0777 leaf inside the
// 0700 root) — not a hand-staged directory — then builds a validateSpec-passing
// SessionSpec from the staged material. The image is the bind-capable guest from
// OCU_RUNTIME_IT_IMAGE. The staging base is OCU_RUNTIME_IT_STAGE_DIR (or t.TempDir)
// so the host-side sock dir is visible to BOTH the test and a remote daemon, the
// same way itSpec resolves its bind sources.
func bindSpec(t *testing.T, name runtime.SessionName, image string) (runtime.SessionSpec, handoff.Staged) {
	t.Helper()
	base := itStageDir(t)
	stager := handoff.NewStager(base)

	pub, _, kerr := ed25519.GenerateKey(nil)
	if kerr != nil {
		t.Fatalf("generate ed25519 key: %v", kerr)
	}
	staged, err := stager.Stage(context.Background(), name, pub, nil)
	if err != nil {
		t.Fatalf("stage handoff: %v", err)
	}
	t.Cleanup(func() { _ = stager.Unstage(context.Background(), staged) })

	// Re-assert the production posture on the staged tree before we hand it to the
	// daemon, so the e2e is a bind against the EXACT perms the fix produces: the
	// sock leaf is 0777 (world-writable enough for a non-owner, CapDrop-ALL'd guest
	// uid to bind) and the root parent is 0700 (walling off every other host user).
	sockInfo, serr := os.Stat(staged.Material.HostSockDir)
	if serr != nil {
		t.Fatalf("stat staged sock dir: %v", serr)
	}
	if perm := sockInfo.Mode().Perm(); perm != 0o777 {
		t.Fatalf("staged sock dir perm = %o, want 0777 (the bind would EACCES for a "+
			"non-owner guest uid otherwise)", perm)
	}
	rootInfo, rerr := os.Stat(staged.Root)
	if rerr != nil {
		t.Fatalf("stat staged root: %v", rerr)
	}
	if perm := rootInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("staged root perm = %o, want 0700 (the wall must not be weakened)", perm)
	}

	pids := int64(128)
	spec := runtime.SessionSpec{
		SchemaVersion: runtime.SchemaV1Alpha,
		Name:          name,
		Owner:         runtime.Identity{Tenant: "it-tenant", Caller: "it-caller"},
		Image:         image,
		Egress: runtime.EgressPolicy{
			DefaultDeny:     true,
			AllowedUpstream: "objectstore.internal",
			FilesystemID:    "fs-it",
		},
		Resources: runtime.ResourceCaps{
			CPUCores:    1,
			MemoryBytes: 256 << 20,
			PidsLimit:   &pids,
		},
		Handoff: staged.Material,
	}
	return spec, staged
}

// TestIT_LiveExecBindUnderCapDropALL is the LIVE control-path bind(2)-under-
// CapDrop-ALL proof. It is the real teeth behind the 0777-sock-leaf posture: the
// provider materializes (creates AND starts) a real guest container under CapDrop
// ALL whose Cmd binds the exec UDS inside the sock dir bound RW at /run/ocu, and
// the test asserts the bind SUCCEEDED by observing the exec socket file appear in
// the host-side bind-mounted sock dir. This is NOT a HostConfig-shape assertion and
// NOT a fake dialer — it is a process performing bind(2) with no CAP_DAC_OVERRIDE
// in a directory it may not own, which only succeeds because the leaf is 0777.
//
// It is gated twice — requireIT (reachable daemon) then requireBindImage (a guest
// image that actually binds under the provider Cmd) — and skips cleanly otherwise,
// so `go test ./...` is green everywhere without OCU_RUNTIME_IT and the e2e runs
// only where both a daemon and a bind-capable guest image are present.
func TestIT_LiveExecBindUnderCapDropALL(t *testing.T) {
	cli := requireIT(t)
	// Resolve the bind-capable image early so the e2e skips cleanly before any
	// daemon work when only the default busybox is available.
	image := requireBindImage(t)
	ctx := context.Background()
	pullIfNeeded(t, cli)

	p, err := NewDockerProvider(runtime.TierRunc, Deps{})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec, staged := bindSpec(t, runtime.SessionName("it-livebind"), image)

	sb, merr := p.Materialize(ctx, spec)
	if merr != nil {
		t.Fatalf("Materialize (create+start under CapDrop ALL): %v", merr)
	}
	t.Cleanup(func() { _ = p.Teardown().ForceKill(context.Background(), sb) })

	// Confirm CapDrop ALL is actually in force on the running container, so the bind
	// we observe below is genuinely a no-CAP_DAC_OVERRIDE bind — the exact condition
	// the 0777 leaf exists to satisfy.
	ci, cerr := cli.ContainerInspect(ctx, sb.RuntimeID)
	if cerr != nil {
		t.Fatalf("container inspect %q: %v", sb.RuntimeID, cerr)
	}
	if ci.HostConfig == nil || !containsString(ci.HostConfig.CapDrop, "ALL") {
		t.Fatalf("CapDrop ALL must hold for the bind-proof to be meaningful, got %+v", ci.HostConfig)
	}

	// The guest binds its exec UDS at guestSockDir/execSockName (/run/ocu/exec.sock),
	// which surfaces host-side as the same leaf name inside the bind-mounted sock dir.
	// Poll for it: the guest needs a moment to come up and call bind(2). The socket
	// file appearing host-side is the proof bind(2) SUCCEEDED in the 0777 dir under
	// CapDrop ALL — an EACCES (the 0700-leaf regression) would leave it absent and
	// crash-loop the guest at bind.
	hostSock := filepath.Join(staged.Material.HostSockDir, execSockName)
	deadline := time.Now().Add(20 * time.Second)
	var bound bool
	for time.Now().Before(deadline) {
		if fi, statErr := os.Stat(hostSock); statErr == nil && fi.Mode()&os.ModeSocket != 0 {
			bound = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !bound {
		// Surface the container state to disambiguate a crash-loop-at-bind (EACCES)
		// from a slow boot when the assertion fails.
		ci2, _ := cli.ContainerInspect(ctx, sb.RuntimeID)
		state := "unknown"
		if ci2.State != nil {
			state = strings.TrimSpace(ci2.State.Status)
		}
		t.Fatalf("exec UDS did not appear host-side at %q within deadline (container state=%q): "+
			"bind(2) likely EACCES'd because the sock leaf is not 0777 — the guest cannot "+
			"bind under CapDrop ALL without it", hostSock, state)
	}
}
