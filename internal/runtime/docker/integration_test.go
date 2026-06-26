// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// itImage is the image the integration tests materialize. It must be present in
// the daemon (or pullable); a tiny coreutils image keeps the test fast. It is set
// via OCU_RUNTIME_IT_IMAGE so a constrained CI mirror can override it; the default
// is the canonical small busybox.
const defaultITImage = "busybox:latest"

// requireIT skips unless OCU_RUNTIME_IT=1 AND a real daemon is reachable. The
// design pins this gate so `go test ./internal/runtime/...` passes everywhere
// (the real daemon lives in a Lima VM on darwin, not on the unit-test host): the
// skip is clean and the suite is green without the env var.
func requireIT(t *testing.T) *client.Client {
	t.Helper()
	if os.Getenv("OCU_RUNTIME_IT") != "1" {
		t.Skip("integration test: set OCU_RUNTIME_IT=1 (real Docker daemon required) to run")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("integration: construct docker client: %v", err)
	}
	if _, perr := cli.Ping(context.Background()); perr != nil {
		t.Skipf("integration test: docker daemon not reachable (%v); skipping", perr)
	}
	return cli
}

func itImage() string {
	if v := os.Getenv("OCU_RUNTIME_IT_IMAGE"); v != "" {
		return v
	}
	return defaultITImage
}

// itStageDir returns the directory the HOST-01 bind sources are staged in. The
// bind mounts are resolved by the DAEMON, not the test process, so when the
// daemon does not share this process's filesystem (a remote DOCKER_HOST — e.g. a
// VM-hosted daemon on a dev laptop), t.TempDir's host-local path does not exist
// in the daemon's view and every ContainerStart fails staging the bind. Setting
// OCU_RUNTIME_IT_STAGE_DIR to a path visible to BOTH the test and the daemon
// (a shared mount) makes the leg runnable against such a daemon; per-test
// isolation is preserved by nesting a unique subdir under it. The default is
// t.TempDir, which is correct for a local daemon (CI), where the two filesystems
// coincide.
func itStageDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("OCU_RUNTIME_IT_STAGE_DIR")
	if base == "" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp(base, "ocu-it-")
	if err != nil {
		t.Fatalf("stage dir under OCU_RUNTIME_IT_STAGE_DIR=%q: %v", base, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// itSpec builds a real, validateSpec-passing SessionSpec backed by on-disk host
// files (the info JSON, the 32-byte public key, and the 0700 sock dir), so the
// three HOST-01 binds resolve against a real daemon: the bind SOURCES are the real
// staged temp files and the bind TARGETS are the in-guest mountpoints (the guest
// root for container_info, /etc/ocu for the key), so source and target differ as
// they do in production. The image runs a long sleep so the container stays up for
// inspection. The staging directory is cleaned up automatically.
func itSpec(t *testing.T, name runtime.SessionName) runtime.SessionSpec {
	t.Helper()
	dir := itStageDir(t)

	infoPath := filepath.Join(dir, "container_info.json")
	if err := os.WriteFile(infoPath, []byte(`{"session":"`+string(name)+`"}`), 0o600); err != nil {
		t.Fatalf("write info json: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	keyPath := filepath.Join(dir, "auth_public_key")
	if err := os.WriteFile(keyPath, pub, 0o600); err != nil {
		t.Fatalf("write pubkey: %v", err)
	}

	sockDir := filepath.Join(dir, "sock")
	if err := os.MkdirAll(sockDir, 0o700); err != nil {
		t.Fatalf("mkdir sock dir: %v", err)
	}

	pids := int64(128)
	return runtime.SessionSpec{
		SchemaVersion: runtime.SchemaV1Alpha,
		Name:          name,
		Owner:         runtime.Identity{Tenant: "it-tenant", Caller: "it-caller"},
		Image:         itImage(),
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
		Handoff: runtime.HandoffMaterial{
			ContainerInfoJSON:      []byte(`{"session":"` + string(name) + `"}`),
			ContainerInfoHostPath:  infoPath,
			ContainerInfoGuestPath: "/container_info.json",
			PublicKeyEd25519:       []byte(pub),
			PublicKeyHostPath:      keyPath,
			PublicKeyGuestPath:     "/etc/ocu/auth_public_key",
			HostSockDir:            sockDir,
		},
	}
}

// TestIT_MaterializeAndInspect materializes a real container on a real per-session
// Internal bridge and asserts via docker inspect that the HOST-01 hardening holds:
// the bridge is Internal, the three binds are present, ReadonlyRootfs and CapDrop
// ALL hold, and no host port is published.
func TestIT_MaterializeAndInspect(t *testing.T) {
	cli := requireIT(t)
	ctx := context.Background()

	pullIfNeeded(t, cli)

	p, err := NewDockerProvider(runtime.TierRunc, Deps{})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec := itSpec(t, runtime.SessionName("it-inspect"))

	sb, merr := p.Materialize(ctx, spec)
	if merr != nil {
		t.Fatalf("Materialize: %v", merr)
	}
	t.Cleanup(func() { _ = p.Teardown().ForceKill(context.Background(), sb) })

	// Bridge is Internal (deny-all).
	ni, nerr := cli.NetworkInspect(ctx, networkName(spec.Name), network.InspectOptions{})
	if nerr != nil {
		t.Fatalf("network inspect %q: %v", networkName(spec.Name), nerr)
	}
	if !ni.Internal {
		t.Errorf("per-session bridge must be Internal, got Internal=%v", ni.Internal)
	}

	// Container hardening via inspect.
	ci, cerr := cli.ContainerInspect(ctx, sb.RuntimeID)
	if cerr != nil {
		t.Fatalf("container inspect %q: %v", sb.RuntimeID, cerr)
	}
	if ci.HostConfig == nil {
		t.Fatalf("inspect returned no HostConfig")
	}
	if !ci.HostConfig.ReadonlyRootfs {
		t.Errorf("ReadonlyRootfs must hold on the real container")
	}
	if !containsString(ci.HostConfig.CapDrop, "ALL") {
		t.Errorf("CapDrop must contain ALL, got %v", ci.HostConfig.CapDrop)
	}
	if len(ci.HostConfig.Binds) != 3 {
		t.Errorf("expected exactly 3 binds, got %d (%v)", len(ci.HostConfig.Binds), ci.HostConfig.Binds)
	}
	// No host port published.
	if len(ci.HostConfig.PortBindings) != 0 {
		t.Errorf("no host port must be published, got %v", ci.HostConfig.PortBindings)
	}
	// The three bind destinations (the in-guest TARGETS) are present as inspected
	// mountpoints: container_info at the guest root default path, the key at the
	// fleet-canon /etc/ocu path, and the sock dir at /run/ocu.
	wantDests := []string{spec.Handoff.ContainerInfoGuestPath, spec.Handoff.PublicKeyGuestPath, "/run/ocu"}
	for _, d := range wantDests {
		if !hasMountDest(ci.Mounts, d) {
			t.Errorf("expected a mount at %q, mounts=%+v", d, ci.Mounts)
		}
	}
}

// TestIT_GracefulStopHonorsGrace asserts GracefulStop issues the SIGTERM-then-kill
// drain and the container is gone afterward, and that NetworkRemove succeeds only
// after the container is removed (the active-endpoints constraint): the bridge is
// gone too.
func TestIT_GracefulStopHonorsGrace(t *testing.T) {
	cli := requireIT(t)
	ctx := context.Background()
	pullIfNeeded(t, cli)

	p, err := NewDockerProvider(runtime.TierRunc, Deps{})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec := itSpec(t, runtime.SessionName("it-graceful"))
	sb, merr := p.Materialize(ctx, spec)
	if merr != nil {
		t.Fatalf("Materialize: %v", merr)
	}

	start := time.Now()
	if terr := p.Teardown().GracefulStop(ctx, sb, runtime.Duration(2)); terr != nil {
		t.Fatalf("GracefulStop: %v", terr)
	}
	// The drain must be bounded by the grace window plus the force-remove; assert
	// it did not hang unboundedly.
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("GracefulStop took %v, expected to be bounded by the grace window", elapsed)
	}

	// Container is gone.
	if _, ierr := cli.ContainerInspect(ctx, sb.RuntimeID); !cerrdefs.IsNotFound(ierr) {
		t.Errorf("container must be gone after GracefulStop, inspect err=%v", ierr)
	}
	// Bridge is gone (NetworkRemove ran after the container removal).
	if _, ierr := cli.NetworkInspect(ctx, networkName(spec.Name), network.InspectOptions{}); !cerrdefs.IsNotFound(ierr) {
		t.Errorf("bridge must be gone after GracefulStop, inspect err=%v", ierr)
	}
}

// requireRunsc skips with a LOUD notice when the daemon has no "runsc" runtime
// registered. It is the second half of the gVisor leg's gate: requireIT proves a
// reachable daemon, then this proves the daemon can actually create a gVisor
// container — otherwise ContainerCreate would fail with "unknown runtime: runsc".
// The skip names the requirement so a green CI is never mistaken for an executed
// gVisor assertion; the CI/Lima runner must register the runsc runtime for this leg
// to run (the stock ubuntu-latest runner does not ship it, so it skips-with-notice
// there until provisioned).
func requireRunsc(t *testing.T, cli *client.Client) {
	t.Helper()
	info, err := cli.Info(context.Background())
	if err != nil {
		t.Skipf("integration: gVisor leg could not query daemon Info (%v); skipping", err)
	}
	if _, ok := info.Runtimes["runsc"]; !ok {
		names := make([]string, 0, len(info.Runtimes))
		for n := range info.Runtimes {
			names = append(names, n)
		}
		t.Skipf("integration: gVisor leg requires runsc registered on the daemon "+
			"(info.Runtimes has no \"runsc\"; registered: %v); the CI/Lima runner must "+
			"register the gVisor runtime — skipping", names)
	}
}

// TestIT_GvisorRuntimeInspect is the real-daemon confirmation of the gVisor wiring:
// a TierGvisor provider materializes a container and docker inspect reports
// HostConfig.Runtime == "runsc", proving the admission-admitted gVisor decision is
// enforced at the OCI layer (the sentry actually runs the workload, not bare runc).
// It is gated twice — requireIT (reachable daemon) then requireRunsc (runsc
// registered) — and skips-with-notice where runsc is absent, never silently
// passing. The unit + fake-SDK + consistency tests make the gap red→green on every
// runner; this leg is the real-runsc confirmation where the runtime exists.
func TestIT_GvisorRuntimeInspect(t *testing.T) {
	cli := requireIT(t)
	requireRunsc(t, cli)
	ctx := context.Background()
	pullIfNeeded(t, cli)

	p, err := NewDockerProvider(runtime.TierGvisor, Deps{})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec := itSpec(t, runtime.SessionName("it-gvisor"))

	sb, merr := p.Materialize(ctx, spec)
	if merr != nil {
		t.Fatalf("Materialize(TierGvisor): %v", merr)
	}
	t.Cleanup(func() { _ = p.Teardown().ForceKill(context.Background(), sb) })

	ci, cerr := cli.ContainerInspect(ctx, sb.RuntimeID)
	if cerr != nil {
		t.Fatalf("container inspect %q: %v", sb.RuntimeID, cerr)
	}
	if ci.HostConfig == nil {
		t.Fatalf("inspect returned no HostConfig")
	}
	if ci.HostConfig.Runtime != "runsc" {
		t.Errorf("TierGvisor container HostConfig.Runtime: want %q (gVisor sentry enforced at OCI), got %q",
			"runsc", ci.HostConfig.Runtime)
	}
}

// TestIT_ForceKillBackstop asserts a container that ignores SIGTERM is
// force-removed promptly with no wait on any guest reply, and that a second
// ForceKill on the same Sandbox is idempotent (no error).
func TestIT_ForceKillBackstop(t *testing.T) {
	cli := requireIT(t)
	ctx := context.Background()
	pullIfNeeded(t, cli)

	p, err := NewDockerProvider(runtime.TierRunc, Deps{})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	spec := itSpec(t, runtime.SessionName("it-force"))
	sb, merr := p.Materialize(ctx, spec)
	if merr != nil {
		t.Fatalf("Materialize: %v", merr)
	}

	start := time.Now()
	if terr := p.Teardown().ForceKill(ctx, sb); terr != nil {
		t.Fatalf("ForceKill: %v", terr)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("ForceKill took %v, must not wait on a guest reply", elapsed)
	}
	if _, ierr := cli.ContainerInspect(ctx, sb.RuntimeID); !cerrdefs.IsNotFound(ierr) {
		t.Errorf("container must be gone after ForceKill, inspect err=%v", ierr)
	}

	// Second ForceKill is idempotent (no error) on the already-gone Sandbox.
	if terr := p.Teardown().ForceKill(ctx, sb); terr != nil {
		t.Errorf("second ForceKill must be idempotent, got %v", terr)
	}
}

// pullIfNeeded ensures the integration image is present, pulling it if the daemon
// does not have it. A pull failure skips rather than fails: a constrained CI
// mirror without registry access still gets a clean skip.
func pullIfNeeded(t *testing.T, cli *client.Client) {
	t.Helper()
	ctx := context.Background()
	if _, err := cli.ImageInspect(ctx, itImage()); err == nil {
		return
	}
	rc, err := cli.ImagePull(ctx, itImage(), image.PullOptions{})
	if err != nil {
		t.Skipf("integration test: image %q absent and pull failed (%v); skipping", itImage(), err)
	}
	defer func() { _ = rc.Close() }()
	// Drain the pull progress so the layers land before we run.
	if _, derr := io.Copy(io.Discard, rc); derr != nil {
		t.Skipf("integration test: image pull drain failed (%v); skipping", derr)
	}
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasMountDest(mounts []container.MountPoint, dest string) bool {
	for i := range mounts {
		if strings.TrimSuffix(mounts[i].Destination, "/") == strings.TrimSuffix(dest, "/") {
			return true
		}
	}
	return false
}
