// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package provisioning_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/provisioning"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// stagedRoot builds a Staged handle over a fresh 0700 host-owned root with the
// 0777 sock leaf inside, mirroring what the handoff stager produces, so the push
// lands inside the real RW-bound sock dir.
func stagedRoot(t *testing.T) handoff.Staged {
	t.Helper()
	root := filepath.Join(t.TempDir(), "session-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	sock := filepath.Join(root, "sock")
	if err := os.Mkdir(sock, 0o777); err != nil {
		t.Fatalf("mkdir sock: %v", err)
	}
	return handoff.Staged{
		Root:     root,
		Material: runtime.HandoffMaterial{HostSockDir: sock},
	}
}

// sampleConfig is a stand-in for the mountcfg.Config.Marshal output: opaque
// host-only bytes the push treats as a sealed payload. The push never parses it.
var sampleConfig = []byte(`{"schema_version":"v1alpha","service_url":"https://filestore.example","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----","mounts":[{"destination":"/mnt/ws","auth_token":"eyJ.fake.jwt","readonly":false,"vfs_cache_mode":"writes","cache_duration_s":30,"vfs_cache_max_size":"512M","dir_perms":"0700","file_perms":"0600","filesystem_id":"fs-abc"}]}`)

// TestPushLandsInSockDir asserts the rendered config lands INSIDE the sock dir
// (the one directory the provider bind-mounts RW into the guest — the handoff
// root itself is never bound) at the fixed name, with byte-identical content and
// the 0644 guest-readable mode (the 0700 root parent is the trust gate; 0600
// would EACCES a userns-remapped guest read), and that the returned GuestPath is
// the in-guest sock-dir mountpoint plus the fixed name.
func TestPushLandsInSockDir(t *testing.T) {
	p := provisioning.NewPusher()
	staged := stagedRoot(t)

	pushed, err := p.Push(context.Background(), staged, sampleConfig)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if pushed.Path == "" {
		t.Fatalf("Push returned an empty path")
	}
	if filepath.Dir(pushed.Path) != staged.Material.HostSockDir {
		t.Fatalf("config landed outside the sock dir (the only bound directory): %q not under %q",
			pushed.Path, staged.Material.HostSockDir)
	}
	if got := filepath.Base(pushed.Path); got != "mount-config.json" {
		t.Fatalf("pushed config name = %q, want the fixed mount-config.json", got)
	}
	if pushed.GuestPath != "/run/ocu/mount-config.json" {
		t.Fatalf("GuestPath = %q, want /run/ocu/mount-config.json (sock-dir mountpoint + fixed name)", pushed.GuestPath)
	}

	info, err := os.Stat(pushed.Path)
	if err != nil {
		t.Fatalf("stat pushed config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("pushed config mode = %o, want 0644 (guest-readable under userns; the 0700 root parent is the trust gate)", got)
	}

	got, err := os.ReadFile(pushed.Path)
	if err != nil {
		t.Fatalf("read pushed config: %v", err)
	}
	if string(got) != string(sampleConfig) {
		t.Fatalf("pushed config bytes differ from input")
	}
}

// TestScrubIdempotent asserts Scrub removes the pushed config AND that a second
// Scrub of the now-gone path is a satisfied no-op (idempotent), so the create
// unwind and the teardown finalizer may both call it without racing.
func TestScrubIdempotent(t *testing.T) {
	p := provisioning.NewPusher()
	staged := stagedRoot(t)

	pushed, err := p.Push(context.Background(), staged, sampleConfig)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	if err := p.Scrub(context.Background(), pushed); err != nil {
		t.Fatalf("first Scrub: %v", err)
	}
	if _, err := os.Stat(pushed.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config still present after Scrub: stat err = %v", err)
	}
	// Second scrub of the already-gone path is a satisfied scrub, not an error.
	if err := p.Scrub(context.Background(), pushed); err != nil {
		t.Fatalf("idempotent Scrub of a gone path: %v", err)
	}
}

// TestScrubEmptyPathNoOp asserts Scrub on a zero Pushed (nothing was pushed) is a
// no-op, mirroring the compensator's handling of a stage that never ran.
func TestScrubEmptyPathNoOp(t *testing.T) {
	p := provisioning.NewPusher()
	if err := p.Scrub(context.Background(), provisioning.Pushed{}); err != nil {
		t.Fatalf("Scrub of empty Pushed: %v", err)
	}
}

// TestScrubTriggersHostSideOnly asserts Scrub reclaims the HOST-side file only:
// after Scrub the host file is gone, but the staged root (the host-owned bind the
// in-guest mount client would read from) survives. Control TRIGGERS the scrub of
// its own pushed artifact; it does NOT perform the in-guest scrub-on-load, which
// is the storage engine's job inside the sandbox (scope boundary).
func TestScrubTriggersHostSideOnly(t *testing.T) {
	p := provisioning.NewPusher()
	staged := stagedRoot(t)

	pushed, err := p.Push(context.Background(), staged, sampleConfig)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := p.Scrub(context.Background(), pushed); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	// The pushed config is gone host-side.
	if _, err := os.Stat(pushed.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host config not reclaimed: %v", err)
	}
	// The staged root and the sock dir (the bind) survive — Scrub does not tear
	// down the handoff tree (that is the handoff Unstage compensator's job), and
	// never reaches into the guest.
	if info, err := os.Stat(staged.Root); err != nil || !info.IsDir() {
		t.Fatalf("staged root removed by Scrub: err=%v", err)
	}
	if info, err := os.Stat(staged.Material.HostSockDir); err != nil || !info.IsDir() {
		t.Fatalf("sock dir removed by Scrub: err=%v", err)
	}
}

// TestPushRefusesEmptySockDir asserts the push fails closed when the Staged
// handoff carries no host-owned sock dir: there is no BOUND directory to land the
// config in. A Root alone is not enough — the root is never bind-mounted into the
// guest, so a root-only Staged must refuse rather than strand the config.
func TestPushRefusesEmptySockDir(t *testing.T) {
	p := provisioning.NewPusher()
	if _, err := p.Push(context.Background(), handoff.Staged{}, sampleConfig); !errors.Is(err, provisioning.ErrNoStagedRoot) {
		t.Fatalf("zero Staged: want ErrNoStagedRoot, got %v", err)
	}
	// Root set but no sock dir: still a refusal — the target is the BOUND sock
	// leaf, never the unbound root.
	rootOnly := handoff.Staged{Root: t.TempDir()}
	if _, err := p.Push(context.Background(), rootOnly, sampleConfig); !errors.Is(err, provisioning.ErrNoStagedRoot) {
		t.Fatalf("root-only Staged (no sock dir): want ErrNoStagedRoot, got %v", err)
	}
}

// TestPushRefusesEmptyConfig asserts the push fails closed on an empty payload, so
// the mount client never boots on a zero-length config.
func TestPushRefusesEmptyConfig(t *testing.T) {
	p := provisioning.NewPusher()
	staged := stagedRoot(t)
	_, err := p.Push(context.Background(), staged, nil)
	if !errors.Is(err, provisioning.ErrEmptyConfig) {
		t.Fatalf("empty config: want ErrEmptyConfig, got %v", err)
	}
	// No file should have been created in the sock dir (the push target).
	entries, err := os.ReadDir(staged.Material.HostSockDir)
	if err != nil {
		t.Fatalf("read staged sock dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty-config push left %d entries behind", len(entries))
	}
}

// TestPushCanceledContext asserts a canceled context is refused before any write,
// fail-closed.
func TestPushCanceledContext(t *testing.T) {
	p := provisioning.NewPusher()
	staged := stagedRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Push(ctx, staged, sampleConfig)
	if !errors.Is(err, provisioning.ErrPushFailed) {
		t.Fatalf("canceled push: want ErrPushFailed, got %v", err)
	}
}
