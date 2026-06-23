// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package handoff stages the host-side handoff material one session needs at
// create: the container_info.json the guest reads at boot, the raw 32-byte
// Ed25519 PUBLIC key the guest verifies host-signed control-RPC frames against,
// and the 0700 host-owned socket directory the guest creates its exec UDS in. It
// produces the runtime.HandoffMaterial the lifecycle layer puts on the
// SessionSpec, plus the per-session root the create's unwind compensator removes
// on rollback.
//
// Fail-closed discipline: Stage refuses (writing nothing that survives) on a
// non-32-byte public key — a malformed key is never substituted by a daemon
// default — and on a short write, so a half-written handoff can never reach a
// container. Unstage removes the whole per-session tree and is idempotent: an
// already-gone root is a satisfied teardown, not an error, so the create unwind
// and a later reconcile can both call it without racing.
//
// The only secret on the create path (the weak Storage-JWT) rides MountIntent,
// not this package; AuthToken stays a later-phase placeholder here. The package
// is pure filesystem and imports internal/runtime only — it holds no Store and no
// clock.
package handoff

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// Filesystem layout constants. Each session gets a 0700 root under the stager's
// base; the three handoff artifacts live at fixed names within it, and the guest
// mountpoints the provider binds them to are fixed absolute paths.
const (
	// dirPerm is the 0700 mode on the per-session root and the sock dir: owner-only
	// so no other host user can read the handoff material or plant a socket.
	dirPerm = 0o700
	// filePerm is the 0600 mode on the written artifacts (owner read/write only).
	filePerm = 0o600

	// containerInfoFile is the on-host filename for the serialized
	// container_info.json within the per-session root.
	containerInfoFile = "container_info.json"
	// publicKeyFile is the on-host filename for the raw 32-byte Ed25519 public key.
	publicKeyFile = "auth_public_key"
	// sockDirName is the per-session sock-dir name within the root; the guest
	// creates its exec UDS here (bound RW at /run/ocu inside the guest).
	sockDirName = "sock"

	// guestContainerInfoPath is the absolute guest mountpoint for container_info.json.
	guestContainerInfoPath = "/etc/ocu/container_info.json"
	// guestPublicKeyPath is the absolute guest mountpoint for the public key. It is
	// the fleet-canon in-guest path the guest image declares and the sandbox's own
	// host-side driver also binds to (the guest-image INTEGRATION.md contract +
	// ocu-sandbox host/internal/control/create.go) — one path across both host
	// drivers that materialize the same guest image.
	guestPublicKeyPath = "/etc/ocu/auth_public_key"
)

// ErrBadPublicKey is the fail-closed refusal for a public key that is not exactly
// ed25519.PublicKeySize (32) bytes. Stage writes nothing that survives and returns
// this wrapped — a malformed key is never substituted by a default, mirroring the
// provider's own non-32-byte refusal (runtime.ErrUnsupportedSpec).
var ErrBadPublicKey = errors.New("handoff: control public key must be exactly 32 bytes")

// ErrStageFailed wraps a filesystem failure during Stage after the per-session
// root was created. Stage removes the partial root before returning, so the
// caller learns the stage failed AND that no half-written handoff survives.
var ErrStageFailed = errors.New("handoff: stage failed (rolled back, nothing survives)")

// Staged is the result of a successful Stage: the runtime.HandoffMaterial to put
// on the SessionSpec, plus the per-session host Root the unwind compensator
// removes. Root is the single thing Unstage needs, so the compensator carries no
// other state across the create.
type Staged struct {
	// Material is the handoff descriptor the provider binds into the container.
	Material runtime.HandoffMaterial
	// Root is the 0700 host-owned per-session directory tree to remove on rollback
	// or teardown. Empty Root means nothing was staged (Unstage is a no-op).
	Root string
}

// Stager writes the host-side handoff material for one session under a per-session
// root it owns. Stage fails closed on a short write or a non-32-byte public key;
// Unstage removes the whole tree and is idempotent. It is pure filesystem; it
// holds no Store and no clock.
type Stager interface {
	// Stage writes container_info.json, the raw 32-byte public key, and the 0700
	// sock dir under a fresh per-session root derived from name, returning the
	// Staged descriptor. mounts is accepted for the later-phase mount-material
	// staging; this phase records the intent on the material but writes no secret
	// (AuthToken stays a placeholder). It returns ErrBadPublicKey on a bad key and
	// ErrStageFailed on a filesystem failure, having removed any partial root.
	Stage(ctx context.Context, name runtime.SessionName, pubKey []byte, mounts []runtime.MountIntent) (Staged, error)
	// Unstage removes the per-session root from st and is idempotent: an
	// already-gone root returns nil, so the create unwind and a later reconcile may
	// both call it. An empty Root is a no-op.
	Unstage(ctx context.Context, st Staged) error
	// SockDir re-derives the per-session 0700 host-owned sock directory PURELY from
	// the host-derived session name, returning the SAME path Stage created under the
	// stager's base root. The path is a pure function of name (base/<name>/sock), so
	// a Destroy path that holds only the session key/name can re-derive the sock dir
	// the advisory control-RPC dial targets WITHOUT the session row persisting it
	// (mirroring how the finalizer re-derives every resource name from SessionName).
	// It writes nothing and is a read-only derivation.
	SockDir(name runtime.SessionName) string
}

// fsStager is the filesystem Stager. It owns a base directory under which every
// per-session root is created; the base is host-configured (e.g. /run/ocu-control/
// handoff) and must already be a host-owned directory.
type fsStager struct {
	base string
}

// NewStager constructs a filesystem Stager rooted at base. Each Stage creates a
// per-session subdirectory of base; base must already exist and be host-owned.
func NewStager(base string) Stager {
	return &fsStager{base: base}
}

// containerInfoFor builds the minimal container_info.json bytes the guest reads
// at boot. The full schema lands with the control-RPC wire in a later phase; this
// phase writes a well-formed JSON object carrying the host-derived session name
// and the guest sock-dir mountpoint, which is what the create path needs now.
func containerInfoFor(name runtime.SessionName) []byte {
	// A hand-built object keeps this package free of a schema dependency the wire
	// contract has not pinned yet; the bytes are valid JSON and stable per name.
	return fmt.Appendf(nil,
		`{"schema":"v1alpha","session_name":%q,"sock_dir":"/run/ocu"}`,
		string(name),
	)
}

// Stage writes the per-session handoff tree. It validates the public key length
// FIRST (fail-closed before any filesystem write), creates the 0700 root and sock
// dir, writes the two :ro artifacts, and returns the Staged descriptor. On any
// filesystem error after the root is created it removes the partial root and
// returns ErrStageFailed, so nothing half-written survives.
func (s *fsStager) Stage(ctx context.Context, name runtime.SessionName, pubKey []byte, mounts []runtime.MountIntent) (Staged, error) {
	if err := ctx.Err(); err != nil {
		return Staged{}, fmt.Errorf("%w: %w", ErrStageFailed, err)
	}
	// Fail closed on a malformed key BEFORE touching the filesystem: a non-32-byte
	// key is never substituted by a default.
	if len(pubKey) != ed25519.PublicKeySize {
		return Staged{}, fmt.Errorf("%w: got %d bytes", ErrBadPublicKey, len(pubKey))
	}

	root := filepath.Join(s.base, string(name))
	if err := os.MkdirAll(root, dirPerm); err != nil {
		return Staged{}, fmt.Errorf("%w: create root: %w", ErrStageFailed, err)
	}
	// Re-assert the mode in case MkdirAll honored a permissive umask on an existing
	// parent; the per-session root must be exactly 0700.
	if err := chmod(root, dirPerm); err != nil {
		return s.failClosed(root, "chmod root", err)
	}

	sockDir := filepath.Join(root, sockDirName)
	if err := os.MkdirAll(sockDir, dirPerm); err != nil {
		return s.failClosed(root, "create sock dir", err)
	}
	if err := chmod(sockDir, dirPerm); err != nil {
		return s.failClosed(root, "chmod sock dir", err)
	}

	infoPath := filepath.Join(root, containerInfoFile)
	if err := writeFileExact(infoPath, containerInfoFor(name)); err != nil {
		return s.failClosed(root, "write container_info.json", err)
	}

	// Copy the key into a fresh slice so the staged material does not alias the
	// caller's buffer.
	keyCopy := make([]byte, ed25519.PublicKeySize)
	copy(keyCopy, pubKey)
	keyPath := filepath.Join(root, publicKeyFile)
	if err := writeFileExact(keyPath, keyCopy); err != nil {
		return s.failClosed(root, "write public key", err)
	}

	// mounts seed the later-phase mount material; this phase carries no secret on
	// the handoff and leaves AuthToken a placeholder, so we only record the count
	// for diagnostics via the JSON object above. The parameter is part of the
	// frozen Stager shape so the later mount-material write needs no signature
	// change.
	_ = mounts

	return Staged{
		Material: runtime.HandoffMaterial{
			ContainerInfoJSON: containerInfoFor(name),
			ContainerInfoPath: guestContainerInfoPath,
			PublicKeyEd25519:  keyCopy,
			PublicKeyPath:     guestPublicKeyPath,
			HostSockDir:       sockDir,
		},
		Root: root,
	}, nil
}

// SockDir re-derives the per-session sock directory purely from name, returning
// the SAME path Stage created (base/<name>/sock). It writes nothing: it is the
// single source of truth for the sock-dir layout, so the create path and the
// Destroy path agree on the host-dialled control UDS location without the session
// row persisting it.
func (s *fsStager) SockDir(name runtime.SessionName) string {
	return filepath.Join(s.base, string(name), sockDirName)
}

// failClosed removes the partial root and returns the wrapped ErrStageFailed, so
// every filesystem failure after root creation leaves nothing behind.
func (s *fsStager) failClosed(root, step string, cause error) (Staged, error) {
	_ = os.RemoveAll(root)
	return Staged{}, fmt.Errorf("%w: %s: %w", ErrStageFailed, step, cause)
}

// Unstage removes the per-session root and is idempotent: os.RemoveAll treats an
// already-gone path as success, so a re-run (create unwind then a later reconcile)
// never errors on the missing tree. An empty Root is a no-op.
func (s *fsStager) Unstage(ctx context.Context, st Staged) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("handoff: unstage: %w", err)
	}
	if st.Root == "" {
		return nil
	}
	if err := os.RemoveAll(st.Root); err != nil {
		return fmt.Errorf("handoff: unstage remove %q: %w", st.Root, err)
	}
	return nil
}

// tempFile is the narrow os.File surface writeFileExact drives — exactly the
// methods it calls on the temp file. The production createTemp returns a real
// *os.File (which satisfies this); a test overrides createTemp to return a fake
// whose Write/Chmod/Sync/Close can fail, so the fail-closed branches (notably the
// short-write guard) are exercised without a real partial-write fault on disk.
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
// test. The compile-time assertion below pins that *os.File satisfies tempFile.
var createTemp = func(dir, pattern string) (tempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// Compile-time proof the real *os.File satisfies the narrow tempFile seam, so the
// production createTemp above type-checks and the test fake matches the same shape.
var _ tempFile = (*os.File)(nil)

// chmod is the directory-mode setter Stage uses to re-assert 0700 on the
// per-session root and sock dir, indirected through a package var so a test can
// inject a chmod failure (not portably reproducible on an owned directory) and
// exercise the chmod failClosed branches. In production it is os.Chmod, never
// reassigned outside a test.
var chmod = os.Chmod

// writeFileExact writes data to path with 0600 mode and verifies the whole
// payload landed: a short write (fewer bytes than data) is treated as a failure,
// so a truncated artifact never reaches a container. It writes to a temp file in
// the same directory and renames it into place, so a reader never sees a partial
// file.
func writeFileExact(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".tmp-handoff-*")
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
