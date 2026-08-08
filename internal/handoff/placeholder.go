// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// placeholderPubKey is a well-formed but non-tenant Ed25519 public key baked
// into a pooled unit's handoff (NFR-SEC-70: zero tenant material pre-claim). It
// is a fixed all-zero-except-marker 32-byte value — never a real signing key's
// public half — so a pooled guest that somehow booted before claim would verify
// NOTHING (no real exec-JWT is signed against it), fail-closed. ClaimSpecialize
// overwrites it with the session's real public key before the guest ever starts.
var placeholderPubKey = func() []byte {
	k := make([]byte, ed25519.PublicKeySize)
	k[0] = 0x00 // an all-zero key: a valid length, a real-key-impossible value
	return k
}()

// StagePlaceholder writes a per-POOL-UNIT handoff root exactly like Stage, but
// under a non-tenant PLACEHOLDER identity carrying zero tenant material
// (NFR-SEC-70): a container_info naming the placeholder, the placeholder public
// key, and the 0777 sock leaf. The pooled container binds these host paths at
// create; ClaimSpecialize overwrites the two :ro files IN PLACE (same inode)
// before the guest starts, so the guest reads the REAL identity at first boot.
//
// It returns the same Staged descriptor Stage does, so the docker warm factory
// builds the pooled container's binds from it unchanged.
func (s *fsStager) StagePlaceholder(ctx context.Context, placeholder runtime.SessionName) (Staged, error) {
	if err := ctx.Err(); err != nil {
		return Staged{}, fmt.Errorf("%w: %w", ErrStageFailed, err)
	}
	root := filepath.Join(s.base, string(placeholder))
	if err := os.MkdirAll(root, dirPerm); err != nil {
		return Staged{}, fmt.Errorf("%w: create placeholder root: %w", ErrStageFailed, err)
	}
	if err := chmod(root, dirPerm); err != nil {
		return s.failClosed(root, "chmod placeholder root", err)
	}
	sockDir := filepath.Join(root, sockDirName)
	if err := os.MkdirAll(sockDir, sockDirPerm); err != nil {
		return s.failClosed(root, "create placeholder sock dir", err)
	}
	if err := chmod(sockDir, sockDirPerm); err != nil {
		return s.failClosed(root, "chmod placeholder sock dir", err)
	}

	infoPath := filepath.Join(root, containerInfoFile)
	if err := writeFileExact(infoPath, containerInfoFor(placeholder), roFilePerm); err != nil {
		return s.failClosed(root, "write placeholder container_info.json", err)
	}
	keyPath := filepath.Join(root, publicKeyFile)
	if err := writeFileExact(keyPath, placeholderPubKey, roFilePerm); err != nil {
		return s.failClosed(root, "write placeholder public key", err)
	}

	return Staged{
		Material: runtime.HandoffMaterial{
			ContainerInfoJSON:      containerInfoFor(placeholder),
			ContainerInfoHostPath:  infoPath,
			ContainerInfoGuestPath: guestContainerInfoPath,
			PublicKeyEd25519:       placeholderPubKey,
			PublicKeyHostPath:      keyPath,
			PublicKeyGuestPath:     guestPublicKeyPath,
			HostSockDir:            sockDir,
		},
		Root: root,
	}, nil
}

// ClaimSpecialize rewrites a pooled unit's handoff IN PLACE at claim, converting
// the placeholder identity to the session's real host-attested identity
// (NFR-SEC-69). It overwrites the container_info (with the real session name)
// and the public key at the SAME host paths the pooled container already binds,
// using a same-INODE truncate-and-write — NEVER a rename. This is load-bearing:
// a live :ro bind resolves to the inode the container was created against, and
// writeFileExact's rename-a-fresh-inode-into-place would leave the running-bind
// pointing at the OLD inode, so the guest would boot with the placeholder
// identity. The guest reads container_info once at boot; ClaimSpecialize runs
// BEFORE ContainerStart, so the same-inode overwrite is what the guest reads.
//
// It returns the specialized HandoffMaterial (real name + key) for the session
// row, and does NOT touch the sock dir (the RW bind the guest writes into).
func (s *fsStager) ClaimSpecialize(ctx context.Context, st Staged, realName runtime.SessionName, realPubKey []byte) (runtime.HandoffMaterial, error) {
	if err := ctx.Err(); err != nil {
		return runtime.HandoffMaterial{}, fmt.Errorf("%w: %w", ErrStageFailed, err)
	}
	if len(realPubKey) != ed25519.PublicKeySize {
		return runtime.HandoffMaterial{}, fmt.Errorf("%w: got %d bytes", ErrBadPublicKey, len(realPubKey))
	}
	if st.Material.ContainerInfoHostPath == "" || st.Material.PublicKeyHostPath == "" {
		return runtime.HandoffMaterial{}, fmt.Errorf("%w: claim on an unstaged placeholder", ErrStageFailed)
	}

	realInfo := containerInfoFor(realName)
	if err := overwriteInPlace(st.Material.ContainerInfoHostPath, realInfo); err != nil {
		return runtime.HandoffMaterial{}, fmt.Errorf("%w: specialize container_info: %w", ErrStageFailed, err)
	}
	keyCopy := make([]byte, ed25519.PublicKeySize)
	copy(keyCopy, realPubKey)
	if err := overwriteInPlace(st.Material.PublicKeyHostPath, keyCopy); err != nil {
		return runtime.HandoffMaterial{}, fmt.Errorf("%w: specialize public key: %w", ErrStageFailed, err)
	}

	mat := st.Material
	mat.ContainerInfoJSON = realInfo
	mat.PublicKeyEd25519 = keyCopy
	return mat, nil
}

// overwriteInPlace truncates the existing file and rewrites its content on the
// SAME inode, so a live bind mount on that inode sees the new bytes. It is the
// deliberate opposite of writeFileExact's rename-a-new-inode approach: a rename
// would break a live :ro bind (the container keeps the inode it was created
// against). It preserves the file's mode; it never creates a new file (a missing
// target is an error — a claim on an unstaged placeholder).
func overwriteInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("open for in-place overwrite: %w", err)
	}
	defer func() { _ = f.Close() }()
	n, werr := f.Write(data)
	if werr != nil {
		return fmt.Errorf("write in place: %w", werr)
	}
	if n != len(data) {
		return fmt.Errorf("short in-place write: wrote %d of %d bytes", n, len(data))
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync in place: %w", err)
	}
	return nil
}
