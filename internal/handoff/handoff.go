// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package handoff stages the host-side handoff material one session needs at
// create: the container_info.json the guest reads at boot, the raw 32-byte
// Ed25519 PUBLIC key the guest verifies host-signed control-RPC frames against,
// and the host-owned socket directory the guest creates its exec UDS in (a 0777
// leaf walled inside the 0700 per-session root, so a CapDrop-ALL'd guest whose
// possibly userns-remapped uid does not own the dir can still bind(2)). It
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
	// dirPerm is the 0700 mode on the per-session root: owner-only so no other host
	// user can read the handoff material or traverse into the sock dir.
	dirPerm = 0o700
	// sockDirPerm is the 0777 mode on the inner sock LEAF. The guest binds(2) its
	// exec UDS here under CapDrop ALL (no CAP_DAC_OVERRIDE), and on a daemon with
	// --userns-remap (or an image whose USER uid differs from the dir owner) the
	// guest's mapped uid does NOT own the dir — a 0700 leaf would EACCES the bind
	// and crash-loop the session. Making only the leaf 0777 lets any guest uid
	// bind(2) the socket while the 0700 root parent (dirPerm above) still walls off
	// every other host user, who cannot traverse into the leaf at all. This matches
	// the sandbox driver's bind-proven posture and is config-independent: it holds
	// regardless of userns-remap or image USER, unlike pinning the container User.
	sockDirPerm = 0o777
	// roFilePerm is the 0644 mode on the two :ro handoff artifacts the GUEST reads
	// at boot — container_info.json and the raw Ed25519 PUBLIC key. The guest reads
	// them under CapDrop ALL (no CAP_DAC_READ_SEARCH), and on a daemon with
	// --userns-remap (or an image USER uid != the file owner) the guest's mapped uid
	// does NOT own the files — a 0600 file would EACCES the read. For the key that is
	// a fail-closed boot crash (load_verifying_key propagates the error); for
	// container_info it is a SILENT identity loss (the guest tolerates the unreadable
	// file and binds an empty name, breaking the JWT sub match). Neither file is a
	// secret — a container name and a PUBLIC key (NFR-SEC-25 forbids bind-mounting a
	// secret, these are not) — so 0644 costs no confidentiality: the 0700 root parent
	// (dirPerm) is the trust gate, no other host user can traverse in to read them.
	// 0644 is the only userns-/uid-mismatch-safe read mode; pinning the container
	// User instead would create a new config-asserted contract seam.
	roFilePerm = 0o644
	// filePerm is the 0600 mode on a private temp artifact (owner read/write only);
	// the two staged :ro files are re-moded to roFilePerm by writeFileExact.
	filePerm = 0o600

	// containerInfoFile is the on-host filename for the serialized
	// container_info.json within the per-session root.
	containerInfoFile = "container_info.json"
	// publicKeyFile is the on-host filename for the raw 32-byte Ed25519 public key.
	publicKeyFile = "auth_public_key"
	// sockDirName is the per-session sock-dir name within the root; the guest
	// creates its exec UDS here (bound RW at /run/ocu inside the guest). It is the
	// 0777 leaf (sockDirPerm) inside the 0700 root so the guest can bind(2) it.
	sockDirName = "sock"

	// guestContainerInfoPath is the absolute in-guest mountpoint for
	// container_info.json: the guest image's hardcoded default-read path, which is
	// the filesystem root. The guest reads container_info.json from root with no
	// override supplied, so this is both the bind TARGET and the guest read path.
	guestContainerInfoPath = "/container_info.json"
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
	// Stage writes container_info.json, the raw 32-byte public key, and the 0777
	// sock leaf (inside the 0700 root) under a fresh per-session root derived from
	// name, returning the
	// Staged descriptor. mounts is accepted for the later-phase mount-material
	// staging; this phase records the intent on the material but writes no secret
	// (AuthToken stays a placeholder). It returns ErrBadPublicKey on a bad key and
	// ErrStageFailed on a filesystem failure, having removed any partial root.
	Stage(ctx context.Context, name runtime.SessionName, pubKey []byte, mounts []runtime.MountIntent) (Staged, error)
	// Unstage removes the per-session root from st and is idempotent: an
	// already-gone root returns nil, so the create unwind and a later reconcile may
	// both call it. An empty Root is a no-op.
	Unstage(ctx context.Context, st Staged) error
	// SockDir re-derives the per-session host-owned sock directory PURELY from
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
// phase writes a well-formed JSON object carrying the host-derived session name,
// the guest's own CONTAINER NAME, and the guest sock-dir mountpoint.
//
// The container_name field is LOAD-BEARING: the guest binds its own identity from
// it at boot (auth/container_info.rs) and rejects any exec-JWT whose sub does not
// equal it (auth/claims.rs). It MUST equal the deterministic container name the
// Materialize path assigns as RuntimeID and the exec-signer mints as sub —
// "ocu-sess-<name>", the same value docker.containerName(name) builds. Emitting
// only session_name (the bare key) left the guest with no bound container name, so
// every exec handshake failed "sub does not match container name".
func containerInfoFor(name runtime.SessionName) []byte {
	// A hand-built object keeps this package free of a schema dependency the wire
	// contract has not pinned yet; the bytes are valid JSON and stable per name.
	// The "ocu-sess-" prefix mirrors docker.containerName (a cross-package literal,
	// not an import, to keep handoff free of the runtime/docker dependency).
	return fmt.Appendf(nil,
		`{"schema":"v1alpha","session_name":%q,"container_name":%q,"sock_dir":"/run/ocu"}`,
		string(name),
		"ocu-sess-"+string(name),
	)
}

// Stage writes the per-session handoff tree. It validates the public key length
// FIRST (fail-closed before any filesystem write), creates the 0700 root and the
// 0777 sock leaf, writes the two :ro artifacts, and returns the Staged descriptor.
// On any
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
	if err := os.MkdirAll(sockDir, sockDirPerm); err != nil {
		return s.failClosed(root, "create sock dir", err)
	}
	// The second chmod is load-bearing: MkdirAll honors the process umask, which
	// would otherwise mask the group/other write bits back off the 0777 leaf. The
	// explicit chmod re-asserts 0777 so the CapDrop-ALL'd guest can bind(2) here
	// regardless of the host umask.
	if err := chmod(sockDir, sockDirPerm); err != nil {
		return s.failClosed(root, "chmod sock dir", err)
	}

	infoPath := filepath.Join(root, containerInfoFile)
	if err := writeFileExact(infoPath, containerInfoFor(name), roFilePerm); err != nil {
		return s.failClosed(root, "write container_info.json", err)
	}

	// Copy the key into a fresh slice so the staged material does not alias the
	// caller's buffer.
	keyCopy := make([]byte, ed25519.PublicKeySize)
	copy(keyCopy, pubKey)
	keyPath := filepath.Join(root, publicKeyFile)
	if err := writeFileExact(keyPath, keyCopy, roFilePerm); err != nil {
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
			ContainerInfoJSON:      containerInfoFor(name),
			ContainerInfoHostPath:  infoPath,
			ContainerInfoGuestPath: guestContainerInfoPath,
			PublicKeyEd25519:       keyCopy,
			PublicKeyHostPath:      keyPath,
			PublicKeyGuestPath:     guestPublicKeyPath,
			HostSockDir:            sockDir,
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
// per-session root and 0777 on the sock leaf (beating the umask), indirected
// through a package var so a test can inject a chmod failure (not portably
// reproducible on an owned directory) and exercise the chmod failClosed branches.
// In production it is os.Chmod, never reassigned outside a test.
var chmod = os.Chmod

// writeFileExact writes data to path with the given mode and verifies the whole
// payload landed: a short write (fewer bytes than data) is treated as a failure,
// so a truncated artifact never reaches a container. It writes to a temp file in
// the same directory and renames it into place, so a reader never sees a partial
// file. The two staged :ro handoff files pass roFilePerm (0644) so a guest whose
// CapDrop-ALL'd, possibly userns-remapped uid does not own the file can still read
// it; the explicit Chmod beats the process umask so the mode lands exactly.
func writeFileExact(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".tmp-handoff-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the temp file on any error path below.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(perm); err != nil {
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
