// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package provisioning is the thin host-only seam that delivers the rendered
// mount-config into the RW sock-dir bind BEFORE the in-guest mount client starts,
// and triggers the scrub that reclaims it on teardown. The config lands INSIDE
// the per-session sock dir — the one directory the provider already bind-mounts
// RW at /run/ocu — never as a new bind: NFR-SEC-25 forbids bind-mounting a secret
// :ro, and the handoff ROOT itself is not bound into the guest, so a root-landed
// config would be stranded host-side. Control OWNS delivery and the
// scrub-trigger; it does NOT perform the in-guest scrub-on-load (that is the
// storage engine's job inside the sandbox — the scope boundary). The package is a
// leaf over internal/handoff and the host filesystem; it holds no clock, no
// Store, and no signing key.
//
// The pushed bytes already carry the revealed weak Storage-JWT (the single
// mountcfg Marshal reveal boundary produced them). This seam treats them as opaque
// host-only bytes: it writes them fail-closed on a short write and NEVER logs them
// — there is no code path here that stringifies or records the payload. The 0644
// file mode is not the confidentiality gate; the 0700 per-session root parent is
// (see filePerm).
package provisioning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
)

const (
	// mountConfigFile is the fixed filename the rendered mount-config lands at,
	// INSIDE the per-session sock dir (the one RW bind the guest already has). The
	// in-guest mount client reads it at guestMountConfigPath; the name is fixed so
	// neither side carries it as a hint.
	mountConfigFile = "mount-config.json"

	// guestSockDirMount is the absolute in-guest mountpoint the provider binds the
	// host-owned sock dir RW at. It mirrors the provider's guestSockDir constant
	// the same way the handoff stager mirrors the guest public-key path — one
	// fleet-canon in-guest path, agreed across the host packages that produce and
	// consume it.
	guestSockDirMount = "/run/ocu"

	// guestMountConfigPath is the absolute in-guest path of the pushed config: the
	// sock-dir mountpoint plus the fixed name. It is the value Pushed.GuestPath
	// carries and the lifecycle sets on HandoffMaterial.MountConfigGuestPath.
	guestMountConfigPath = guestSockDirMount + "/" + mountConfigFile

	// filePerm is the 0644 mode on the pushed config. The mode is NOT the trust
	// gate — the 0700 per-session root parent is: no other host user can traverse
	// into the sock leaf at all, so 0644 costs no host-side confidentiality. It IS
	// the only userns-/uid-mismatch-safe read mode (the handoff stager's proven
	// guest-read posture): the guest reads the config under CapDrop ALL as a
	// possibly userns-remapped uid that does NOT own the file, and a 0600 file
	// would EACCES that read — a mount-config-missing fail-SILENT invariant loss
	// (the guest boots, the mount never comes up, nothing downstream notices).
	filePerm = 0o644
)

var (
	// ErrNoStagedRoot is the fail-closed refusal when the Staged handoff carries no
	// host-owned sock dir: there is no bound directory to land the config in, so
	// the push refuses rather than writing to a path the guest can never read.
	ErrNoStagedRoot = errors.New("provisioning: refused to push, staged handoff has no host-owned sock dir")

	// ErrEmptyConfig is the fail-closed refusal for an empty payload: a zero-length
	// mount-config never reaches the bind, so the mount client never boots on an
	// empty config.
	ErrEmptyConfig = errors.New("provisioning: refused to push an empty mount-config")

	// ErrPushFailed wraps a filesystem failure during Push. The partial temp file is
	// removed before returning, so a half-written config never reaches the mount
	// client (fail-closed).
	ErrPushFailed = errors.New("provisioning: push failed (rolled back, nothing survives)")
)

// Pushed is the handle the finalizer scrubs: the host-side path the rendered
// mount-config landed at, plus the in-guest path the mount client reads it from.
// Control owns delivery plus the scrub-trigger; the in-guest scrub-on-load is not
// represented here (scope boundary).
type Pushed struct {
	// Path is the host-owned file the rendered mount-config landed at, inside the
	// per-session sock dir (the RW bind). An empty Path means nothing was pushed
	// (Scrub is a no-op).
	Path string
	// GuestPath is the absolute in-guest path the mount client reads the config at
	// — the sock-dir mountpoint plus the fixed name. The lifecycle sets it on
	// HandoffMaterial.MountConfigGuestPath; it is both-or-neither with Path.
	GuestPath string
}

// Pusher writes the rendered mount-config into the host-owned handoff bind before
// the mount client starts and removes it on teardown. It is a leaf over the
// handoff root and the host filesystem.
type Pusher interface {
	// Push writes cfgBytes (the mountcfg.Config.Marshal output) into staged's
	// host-owned sock dir at the fixed mount-config name, fail-closed on a short
	// write, and returns the host + in-guest paths. cfgBytes already carries the
	// revealed token; this seam treats it as opaque host-only bytes and never logs
	// them. It runs BEFORE materialize, so the config is on the bind before the
	// in-guest mount client boots.
	Push(ctx context.Context, staged handoff.Staged, cfgBytes []byte) (Pushed, error)
	// Scrub removes the pushed config host-side (Control's scrub-trigger). It is
	// idempotent: an already-gone file is a satisfied scrub, so the create unwind
	// compensator and the teardown finalizer may both call it without racing.
	Scrub(ctx context.Context, p Pushed) error
}

// fsPusher is the filesystem Pusher. It is stateless: every path it touches is
// derived from the Staged root it is handed, so it survives a process restart with
// no provider state.
type fsPusher struct{}

// NewPusher constructs the filesystem Pusher. It holds no state.
func NewPusher() Pusher {
	return fsPusher{}
}

// Push writes cfgBytes to HostSockDir/mount-config.json, fail-closed: it refuses
// a Staged with no sock dir or an empty payload, writes to a temp file in the
// same directory, verifies the whole payload landed (a short write is a
// failure), and renames it into place so the mount client never reads a partial
// config. On any filesystem error it removes the partial temp file and returns
// ErrPushFailed.
//
// The target is the SOCK DIR (staged.Material.HostSockDir), not the handoff
// root: the sock dir is the one directory the provider bind-mounts RW at
// guestSockDirMount, so the config rides the existing bind and the guest reads
// it at guestMountConfigPath. The handoff root itself is never bound into the
// guest — a root-landed config would be stranded host-side.
func (fsPusher) Push(ctx context.Context, staged handoff.Staged, cfgBytes []byte) (Pushed, error) {
	if err := ctx.Err(); err != nil {
		return Pushed{}, fmt.Errorf("%w: %w", ErrPushFailed, err)
	}
	if staged.Material.HostSockDir == "" {
		return Pushed{}, ErrNoStagedRoot
	}
	if len(cfgBytes) == 0 {
		return Pushed{}, ErrEmptyConfig
	}

	path := filepath.Join(staged.Material.HostSockDir, mountConfigFile)
	if err := writeFileExact(path, cfgBytes); err != nil {
		return Pushed{}, fmt.Errorf("%w: write mount-config: %w", ErrPushFailed, err)
	}
	return Pushed{Path: path, GuestPath: guestMountConfigPath}, nil
}

// Scrub removes the pushed config and is idempotent: os.Remove on an already-gone
// path is treated as success (a satisfied scrub), so the create unwind and the
// teardown finalizer may both call it. An empty Path is a no-op. Control TRIGGERS
// the reclamation host-side here; the in-guest scrub-on-load is not performed
// (scope boundary).
func (fsPusher) Scrub(ctx context.Context, p Pushed) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("provisioning: scrub: %w", err)
	}
	if p.Path == "" {
		return nil
	}
	if err := os.Remove(p.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("provisioning: scrub remove %q: %w", p.Path, err)
	}
	return nil
}

// tempFile is the narrow os.File surface writeFileExact drives. A test overrides
// createTemp to return a fake whose Write/Chmod/Sync/Close can fail, exercising the
// fail-closed branches (notably the short-write guard) without a real partial-write
// fault on disk. It mirrors the handoff package's seam so the two write paths share
// one fault-injection shape.
type tempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// createTemp is the temp-file constructor writeFileExact uses, indirected through a
// package var so a test can inject a fault-injecting fake. In production it is the
// stdlib os.CreateTemp returning a real *os.File; it is never reassigned outside a
// test.
var createTemp = func(dir, pattern string) (tempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// Compile-time proof the real *os.File satisfies the narrow tempFile seam.
var _ tempFile = (*os.File)(nil)

// writeFileExact writes data to path at filePerm and verifies the whole payload
// landed: a short write (fewer bytes than data) is a failure, so a truncated config
// never reaches the mount client. It writes to a temp file in the same directory
// and renames it into place, so a reader never sees a partial file.
func writeFileExact(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".tmp-mountcfg-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the temp file on any error path below.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	n, werr := tmp.Write(data)
	if werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", werr)
	}
	if n != len(data) {
		_ = tmp.Close()
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
