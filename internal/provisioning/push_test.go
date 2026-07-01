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
)

// stagedRoot builds a Staged handle over a fresh 0700 host-owned root, mirroring
// what the handoff stager produces, so the push lands on a real host-owned bind.
func stagedRoot(t *testing.T) handoff.Staged {
	t.Helper()
	root := filepath.Join(t.TempDir(), "session-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	return handoff.Staged{Root: root}
}

// sampleConfig is a stand-in for the mountcfg.Config.Marshal output: opaque
// host-only bytes the push treats as a sealed payload. The push never parses it.
var sampleConfig = []byte(`{"schema_version":"v1alpha","service_url":"https://filestore.example","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----","mounts":[{"destination":"/mnt/ws","auth_token":"eyJ.fake.jwt","readonly":false,"vfs_cache_mode":"writes","cache_duration_s":30,"vfs_cache_max_size":"512M","dir_perms":"0700","file_perms":"0600","filesystem_id":"fs-abc"}]}`)

// TestPushLandsAt0600 asserts the rendered config lands on the host-owned bind at
// the fixed name with EXACTLY 0600 owner-only mode and byte-identical content (the
// bytes are opaque to the push; the mount client reads them verbatim).
func TestPushLandsAt0600(t *testing.T) {
	p := provisioning.NewPusher()
	staged := stagedRoot(t)

	pushed, err := p.Push(context.Background(), staged, sampleConfig)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if pushed.Path == "" {
		t.Fatalf("Push returned an empty path")
	}
	if filepath.Dir(pushed.Path) != staged.Root {
		t.Fatalf("config landed outside the staged root: %q not under %q", pushed.Path, staged.Root)
	}

	info, err := os.Stat(pushed.Path)
	if err != nil {
		t.Fatalf("stat pushed config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("pushed config mode = %o, want 0600", got)
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
	// The staged root (the bind) survives — Scrub does not tear down the handoff
	// tree (that is the handoff Unstage compensator's job), and never reaches into
	// the guest.
	if info, err := os.Stat(staged.Root); err != nil || !info.IsDir() {
		t.Fatalf("staged root removed by Scrub: err=%v", err)
	}
}

// TestPushRefusesEmptyRoot asserts the push fails closed when the Staged handoff
// carries no host-owned root: there is nowhere host-owned to land the config.
func TestPushRefusesEmptyRoot(t *testing.T) {
	p := provisioning.NewPusher()
	_, err := p.Push(context.Background(), handoff.Staged{}, sampleConfig)
	if !errors.Is(err, provisioning.ErrNoStagedRoot) {
		t.Fatalf("empty root: want ErrNoStagedRoot, got %v", err)
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
	// No file should have been created in the root.
	entries, err := os.ReadDir(staged.Root)
	if err != nil {
		t.Fatalf("read staged root: %v", err)
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
