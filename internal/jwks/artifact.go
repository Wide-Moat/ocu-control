// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// ErrEmptyKeySet is the fail-closed refusal WriteArtifact returns when asked to
// render an empty key set: an empty JWKS document would make the egress edge
// reject every Storage-JWT (no published key matches any token kid) and would
// mask a misconfiguration (a missing signer). The artifact is never written when
// there is nothing to publish — the fence lives here so the helper is fail-closed
// regardless of which caller reaches it.
var ErrEmptyKeySet = errors.New("jwks: refusing to write an empty JWK set")

// artifactPerm is the mode of the written JWKS document. It is intentionally
// world-readable (0644), NOT the 0600 the host's private/secret-adjacent files
// (internal/handoff, internal/provisioning) carry: the content is PUBLIC keys,
// and the deploy layer (a static-file sidecar / nginx / CDN / ingress) must read
// it to serve it at the egress edge's remote_jwks URI (ADR-0019 §35). The
// temp+fsync+rename below keeps the write atomic regardless of the wider mode.
const artifactPerm = 0o644

// WriteArtifact renders the JWKS for pub and writes it ATOMICALLY to path as a
// world-readable static document the deploy layer serves at the egress edge's
// remote_jwks URI (ADR-0019 §35). It reuses Publish for the Set — it does NOT
// reimplement JWK serialization — and carries ONLY public key material (each
// cred.PublicKey holds only the public half; the JWK struct has no private
// member by construction).
//
// It is fail-closed on an empty key set (ErrEmptyKeySet) so an empty JWKS — which
// would make the edge reject every token — is never written, and it propagates
// Publish's ErrUnsupportedKey so an unrenderable key is never silently dropped
// from the served set. The rendered Set reflects pub EXACTLY: a caller hands it
// signer.PublicKeys() (the active key plus, during the rotation overlap, the
// just-superseded key), so the served document can never lag the signer's
// current public keys at render time. v1 has NO live rotation hook (cred rotates
// only via an operator/boot-driven KeySet.Rotate, which the daemon does not call
// at runtime), so the render trigger is boot/restart; when a live rotation seam
// lands, its caller re-invokes WriteArtifact over the same path and the served
// document re-renders to the new active+overlap set through the same atomic
// primitive.
//
// WriteArtifact adds NO network surface: it performs disk syscalls only
// (os.CreateTemp, Write, Sync, Close, os.Rename). It opens no listener and serves
// nothing — the deploy layer, not Control, serves the file.
func WriteArtifact(path string, pub []cred.PublicKey) error {
	// Fail-closed FIRST, before any filesystem touch: an empty key set is never
	// written as an empty JWKS document.
	if len(pub) == 0 {
		return ErrEmptyKeySet
	}
	set, err := Publish(pub)
	if err != nil {
		// An unrenderable key is a hard ErrUnsupportedKey, never a silent omission —
		// a live token could have been minted under it.
		return err
	}
	// Defensive: Publish of a non-empty pub yields a non-empty set, but keeping
	// "never write an empty Set" a local invariant is cheap and removes any
	// dependence on Publish's behaviour.
	if len(set.Keys) == 0 {
		return ErrEmptyKeySet
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal jwks: %w", err)
	}
	// A trailing newline makes the served document well-formed for line-oriented
	// tooling without affecting JSON parsing.
	data = append(data, '\n')
	return writeAtomic(path, data)
}

// tempFile is the narrow os.File surface writeAtomic drives — exactly the methods
// it calls on the temp file. The production createTemp returns a real *os.File
// (which satisfies this); a test overrides createTemp to return a fake whose
// Chmod/Write/Sync/Close can fail, so the fail-closed branches (the short-write
// guard and the chmod/sync/close faults) are exercised without a real partial-
// write fault on disk. It mirrors the same seam in internal/handoff.
type tempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// createTemp is the temp-file constructor writeAtomic uses, indirected through a
// package var so a test can inject a fault-injecting fake. In production it is the
// stdlib os.CreateTemp returning a real *os.File; it is never reassigned outside a
// test. The compile-time assertion below pins that *os.File satisfies tempFile.
var createTemp = func(dir, pattern string) (tempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// Compile-time proof the real *os.File satisfies the narrow tempFile seam, so the
// production createTemp above type-checks and the test fake matches the same shape.
var _ tempFile = (*os.File)(nil)

// writeAtomic writes data to path atomically: it writes to a temp file in the
// SAME directory, fsyncs it, then renames it over the destination. A rename
// within a directory is atomic on POSIX, so a reader (the deploy layer / the
// edge) opening path sees either the OLD complete file or the NEW complete file,
// never a half-written Set — on the initial render AND on every rotation
// re-render. The ordering is load-bearing: write -> verify the full length
// landed -> Sync (fsync the bytes to the temp inode) -> Close -> Rename (re-point
// the directory entry).
//
// It mirrors the house writeFileExact pattern (internal/handoff,
// internal/provisioning) with one deliberate, documented deviation: the mode is
// 0644, not 0600, because the content is PUBLIC keys the deploy layer must read.
// os.CreateTemp creates the temp 0600 by default; the explicit Chmod widens it to
// the world-readable JWKS posture before the rename.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".tmp-jwks-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup of the temp file on any error path below, so a failed
	// render leaves no stray .tmp-jwks-* behind. On the success path the rename has
	// already consumed the temp, so the Remove is a harmless no-op.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(artifactPerm); err != nil {
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
