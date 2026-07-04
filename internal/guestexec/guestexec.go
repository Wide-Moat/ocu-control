// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package guestexec is the control-plane exec-channel driver (ADR-0024): the
// host side that dials the exec socket the handoff staged for one session,
// authenticates with a per-dial container-bound Session JWT, and drives one
// process through the frozen exec-channel wire (contracts/exec).
//
// It consumes ONLY the docker-free client surface of the shared exec module
// (dial + wire) — the docker-touching manager subtree stays in the sandbox
// host; container materialization here is the RuntimeProvider's job. This is
// a DISTINCT channel from the advisory control-RPC shutdown dialer
// (internal/controlrpc, ADR-0018): same sock directory trust gate, different
// socket, different wire.
package guestexec

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-sandbox/host/exec/dial"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// execMinter is the NARROW mint seam this package depends on. It is satisfied
// by *cred.Signer but names only MintExecJWT, so the driver depends on the mint
// method, never the whole custody Signer (and never the signing key).
type execMinter interface {
	MintExecJWT(ctx context.Context, req cred.ExecMintReq) (cred.Token, error)
}

// Compile-time proof *cred.Signer satisfies the narrow seam, so the production
// wiring type-checks and a test fake matches the same shape.
var _ execMinter = (*cred.Signer)(nil)

// Minter adapts the control-plane exec-JWT mint to the exec channel's
// dial.Minter contract for ONE container: every Mint is bound to that
// container_name (sub), so a dial can never present a token for a different
// guest. The raw compact token is revealed only to the dial handshake.
type Minter struct {
	mint          execMinter
	containerName string
}

// Compile-time proof the adapter satisfies the exec channel's dial contract.
var _ dial.Minter = (*Minter)(nil)

// NewMinter binds a mint seam to one container name. An empty container name is
// refused: an unbound Session JWT must be unrepresentable (the mint itself also
// refuses it — this keeps the invalid adapter from existing at all).
func NewMinter(mint execMinter, containerName string) (*Minter, error) {
	if containerName == "" {
		return nil, errors.New("guestexec: empty container name")
	}
	return &Minter{mint: mint, containerName: containerName}, nil
}

// Mint mints the per-dial Session JWT bound to the adapter's container. The
// dial.Minter contract carries no context; the mint is a local signing
// operation (never a network call), so a Background context bounded by nothing
// is sound — the dial itself is bounded by the caller's dial context.
func (m *Minter) Mint(ttl time.Duration) (string, error) {
	tok, err := m.mint.MintExecJWT(context.Background(), cred.ExecMintReq{
		ContainerName: m.containerName,
		RequestedTTL:  ttl,
	})
	if err != nil {
		return "", err
	}
	return tok.Reveal(), nil
}

// ErrSockDirGate is returned when the host-owned gate on the exec sock directory
// fails. The dial is refused BEFORE any connect(2), so a socket planted in a
// non-host-owned or world-traversable location is never spoken to (the same
// host-only-at-accept realization the control-RPC dialer enforces).
var ErrSockDirGate = errors.New("guestexec: exec sock dir failed the host-owned gate")

// verifyHostOwnedDir is the pre-connect trust gate on the staged sock directory.
// The staged layout is a 0700 per-session ROOT with a 0777 sock LEAF inside it:
// the leaf is deliberately world-writable so the CapDrop-ALL guest can bind(2) its
// socket, and the 0700 root PARENT is the trust wall — no other host user can
// traverse into the root, so no non-host peer can plant a socket the host would
// dial. The gate therefore asserts:
//
//   - the sock leaf exists, is a directory, and is owned by the dialing host uid
//     (a leaf owned by another uid is not host-staged); its OWN mode is NOT
//     checked — 0777 is by design, and gating on it here rejected every real exec.
//   - the parent root is a directory, is owned by the dialing host uid, and carries
//     NO group/other permission bits (exactly 0700) — the traversal wall.
func verifyHostOwnedDir(sockDir string) error {
	if sockDir == "" {
		return fmt.Errorf("%w: empty sock dir", ErrSockDirGate)
	}
	// The leaf: a host-owned directory. Its 0777 mode is intended (guest bind(2)).
	leaf, err := os.Stat(sockDir)
	if err != nil {
		return fmt.Errorf("%w: stat %q: %v", ErrSockDirGate, sockDir, err)
	}
	if !leaf.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", ErrSockDirGate, sockDir)
	}
	if err := assertHostOwned(sockDir, leaf); err != nil {
		return err
	}
	// The parent root: host-owned AND exactly 0700 (the traversal wall).
	parent := filepath.Dir(sockDir)
	pinfo, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("%w: stat parent %q: %v", ErrSockDirGate, parent, err)
	}
	if !pinfo.IsDir() {
		return fmt.Errorf("%w: parent %q is not a directory", ErrSockDirGate, parent)
	}
	if pinfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: parent %q mode %o is looser than 0700", ErrSockDirGate, parent, pinfo.Mode().Perm())
	}
	return assertHostOwned(parent, pinfo)
}

// assertHostOwned refuses a path whose owner uid is not the dialing host process's
// effective uid. Geteuid returns -1 where unsupported; the uid is bounded before
// the narrowing conversion so a uid outside the file-owner space cannot wrap.
func assertHostOwned(path string, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %q has no ownership metadata", ErrSockDirGate, path)
	}
	euid := os.Geteuid()
	if euid >= 0 && uint64(euid) <= math.MaxUint32 && st.Uid != uint32(euid) {
		return fmt.Errorf("%w: %q owner uid %d is not the host uid %d", ErrSockDirGate, path, st.Uid, euid)
	}
	return nil
}
