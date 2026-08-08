// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"syscall"
	"testing"
)

func newStager(t *testing.T) *fsStager {
	t.Helper()
	return &fsStager{base: t.TempDir()}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform; cannot assert inode identity")
	}
	return st.Ino
}

func realKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

// TestStagePlaceholder_WritesNonTenantHandoff pins that a placeholder root
// carries the placeholder identity and the placeholder (non-tenant) key — zero
// real tenant material (NFR-SEC-70).
func TestStagePlaceholder_WritesNonTenantHandoff(t *testing.T) {
	s := newStager(t)
	st, err := s.StagePlaceholder(context.Background(), "ocu-pool-1")
	if err != nil {
		t.Fatalf("StagePlaceholder: %v", err)
	}

	info, err := os.ReadFile(st.Material.ContainerInfoHostPath)
	if err != nil {
		t.Fatalf("read placeholder container_info: %v", err)
	}
	if !bytes.Contains(info, []byte("ocu-pool-1")) {
		t.Errorf("placeholder container_info does not name the placeholder: %s", info)
	}
	key, err := os.ReadFile(st.Material.PublicKeyHostPath)
	if err != nil {
		t.Fatalf("read placeholder key: %v", err)
	}
	if !bytes.Equal(key, placeholderPubKey) {
		t.Error("placeholder key is not the non-tenant placeholder key")
	}
	// The sock leaf exists and is 0777 so a CapDrop-ALL guest can bind(2).
	if fi, err := os.Stat(st.Material.HostSockDir); err != nil || fi.Mode().Perm() != sockDirPerm {
		t.Errorf("placeholder sock dir mode = %v err=%v, want %v", fi.Mode().Perm(), err, sockDirPerm)
	}
}

// TestClaimSpecialize_PreservesInodeAndSwapsIdentity is the keystone. The claim
// overwrite MUST keep the SAME inode (a live :ro bind resolves to the inode the
// container was created against, so a rename-a-new-inode write would leave the
// guest reading the placeholder). It asserts the inode is unchanged AND the
// content is now the real session identity and key.
func TestClaimSpecialize_PreservesInodeAndSwapsIdentity(t *testing.T) {
	s := newStager(t)
	st, err := s.StagePlaceholder(context.Background(), "ocu-pool-7")
	if err != nil {
		t.Fatalf("StagePlaceholder: %v", err)
	}
	infoIno := inode(t, st.Material.ContainerInfoHostPath)
	keyIno := inode(t, st.Material.PublicKeyHostPath)

	rk := realKey(t)
	mat, err := s.ClaimSpecialize(context.Background(), st, "sess-real-42", rk)
	if err != nil {
		t.Fatalf("ClaimSpecialize: %v", err)
	}

	// INODE IDENTITY — the load-bearing property: same inode after the overwrite.
	if got := inode(t, st.Material.ContainerInfoHostPath); got != infoIno {
		t.Errorf("container_info inode changed %d -> %d; a live bind would still see the placeholder", infoIno, got)
	}
	if got := inode(t, st.Material.PublicKeyHostPath); got != keyIno {
		t.Errorf("public key inode changed %d -> %d; a live bind would still see the placeholder key", keyIno, got)
	}

	// CONTENT — now the real session identity and key.
	info, _ := os.ReadFile(st.Material.ContainerInfoHostPath)
	if !bytes.Contains(info, []byte("sess-real-42")) || bytes.Contains(info, []byte("ocu-pool-7")) {
		t.Errorf("container_info after claim = %s, want the real session name and no placeholder", info)
	}
	if !bytes.Contains(info, []byte("ocu-sess-sess-real-42")) {
		t.Errorf("container_info does not carry the real bound container_name: %s", info)
	}
	key, _ := os.ReadFile(st.Material.PublicKeyHostPath)
	if !bytes.Equal(key, rk) {
		t.Error("public key after claim is not the real session key")
	}
	if bytes.Equal(key, placeholderPubKey) {
		t.Error("public key after claim is still the placeholder key")
	}

	// The returned material reflects the real identity for the session row.
	if !bytes.Contains(mat.ContainerInfoJSON, []byte("sess-real-42")) {
		t.Error("returned material still carries the placeholder container_info")
	}
	if !bytes.Equal(mat.PublicKeyEd25519, rk) {
		t.Error("returned material still carries the placeholder key")
	}
}

// TestClaimSpecialize_RejectsBadKey pins the fail-closed key check.
func TestClaimSpecialize_RejectsBadKey(t *testing.T) {
	s := newStager(t)
	st, _ := s.StagePlaceholder(context.Background(), "ocu-pool-2")
	if _, err := s.ClaimSpecialize(context.Background(), st, "sess", []byte{1, 2, 3}); err == nil {
		t.Fatal("ClaimSpecialize accepted a 3-byte key")
	}
}

// TestClaimSpecialize_RejectsUnstaged pins that a claim on an empty Staged
// (never StagePlaceholder'd) is refused rather than creating stray files.
func TestClaimSpecialize_RejectsUnstaged(t *testing.T) {
	s := newStager(t)
	_, err := s.ClaimSpecialize(context.Background(), Staged{}, "sess", realKey(t))
	if err == nil || !strings.Contains(err.Error(), "unstaged") {
		t.Fatalf("ClaimSpecialize on an unstaged placeholder = %v, want an unstaged refusal", err)
	}
}

// TestOverwriteInPlace_RefusesMissingFile pins that the in-place writer never
// CREATES a file (that would be a rename-equivalent new inode); a missing target
// is an error.
func TestOverwriteInPlace_RefusesMissingFile(t *testing.T) {
	if err := overwriteInPlace(newStager(t).base+"/does-not-exist", []byte("x")); err == nil {
		t.Fatal("overwriteInPlace created a missing file; it must only truncate an existing inode")
	}
}

// TestStagePlaceholder_CancelledContext covers the fail-closed ctx guard.
func TestStagePlaceholder_CancelledContext(t *testing.T) {
	s := newStager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.StagePlaceholder(ctx, "ocu-pool-x"); err == nil {
		t.Fatal("StagePlaceholder ran with a cancelled context")
	}
}

// TestClaimSpecialize_CancelledContext covers the fail-closed ctx guard on claim.
func TestClaimSpecialize_CancelledContext(t *testing.T) {
	s := newStager(t)
	st, _ := s.StagePlaceholder(context.Background(), "ocu-pool-y")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ClaimSpecialize(ctx, st, "sess", realKey(t)); err == nil {
		t.Fatal("ClaimSpecialize ran with a cancelled context")
	}
}

// TestStagePlaceholder_UnwritableBase covers the mkdir failure branch: a base
// that is a FILE, not a directory, makes MkdirAll of the root fail, and
// StagePlaceholder returns ErrStageFailed rather than a partial root.
func TestStagePlaceholder_UnwritableBase(t *testing.T) {
	dir := t.TempDir()
	fileBase := dir + "/not-a-dir"
	if err := os.WriteFile(fileBase, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &fsStager{base: fileBase} // base is a file; MkdirAll(base/<name>) fails
	if _, err := s.StagePlaceholder(context.Background(), "ocu-pool-z"); err == nil {
		t.Fatal("StagePlaceholder succeeded with a file as its base dir")
	}
}

// TestClaimSpecialize_OverwriteFailureSurfaces covers the overwrite-failure arm:
// if the container_info file is removed after staging (so the in-place overwrite
// cannot open it), ClaimSpecialize fails closed rather than silently proceeding.
func TestClaimSpecialize_OverwriteFailureSurfaces(t *testing.T) {
	s := newStager(t)
	st, err := s.StagePlaceholder(context.Background(), "ocu-pool-of")
	if err != nil {
		t.Fatalf("StagePlaceholder: %v", err)
	}
	// Delete the staged container_info so overwriteInPlace's open fails.
	if err := os.Remove(st.Material.ContainerInfoHostPath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpecialize(context.Background(), st, "sess", realKey(t)); err == nil {
		t.Fatal("ClaimSpecialize succeeded with a missing container_info file")
	}
}

// TestClaimSpecialize_KeyOverwriteFailureSurfaces covers the key-overwrite arm:
// the container_info overwrite succeeds but the key file is gone, so the second
// in-place overwrite fails and ClaimSpecialize fails closed.
func TestClaimSpecialize_KeyOverwriteFailureSurfaces(t *testing.T) {
	s := newStager(t)
	st, err := s.StagePlaceholder(context.Background(), "ocu-pool-kf")
	if err != nil {
		t.Fatalf("StagePlaceholder: %v", err)
	}
	if err := os.Remove(st.Material.PublicKeyHostPath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimSpecialize(context.Background(), st, "sess", realKey(t)); err == nil {
		t.Fatal("ClaimSpecialize succeeded with a missing key file")
	}
}
