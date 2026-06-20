// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package handoff_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// freshPubKey returns a valid 32-byte Ed25519 public key.
func freshPubKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

// newStager builds a filesystem Stager rooted at a fresh temp base.
func newStager(t *testing.T) handoff.Stager {
	t.Helper()
	return handoff.NewStager(t.TempDir())
}

// TestStageWritesAllArtifacts proves a successful Stage writes container_info.json,
// the 32-byte public key, and the 0700 sock dir, and returns material pointing at
// the guest mountpoints.
func TestStageWritesAllArtifacts(t *testing.T) {
	t.Parallel()
	s := newStager(t)
	pub := freshPubKey(t)

	st, err := s.Stage(context.Background(), "sess-1", pub, nil)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if st.Root == "" {
		t.Fatalf("Stage returned empty Root")
	}

	// The material carries the raw 32-byte key and the guest paths.
	if len(st.Material.PublicKeyEd25519) != ed25519.PublicKeySize {
		t.Fatalf("material public key = %d bytes, want %d", len(st.Material.PublicKeyEd25519), ed25519.PublicKeySize)
	}
	if st.Material.ContainerInfoPath == "" || st.Material.PublicKeyPath == "" || st.Material.HostSockDir == "" {
		t.Fatalf("material has an empty mountpoint: %+v", st.Material)
	}

	// The sock dir exists on disk at 0700.
	info, err := os.Stat(st.Material.HostSockDir)
	if err != nil {
		t.Fatalf("stat sock dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("sock dir is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("sock dir perm = %o, want 0700", perm)
	}

	// The root is 0700.
	rootInfo, err := os.Stat(st.Root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if perm := rootInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("root perm = %o, want 0700", perm)
	}

	// The two artifacts exist with the staged byte content.
	infoBytes, err := os.ReadFile(filepath.Join(st.Root, "container_info.json"))
	if err != nil {
		t.Fatalf("read container_info.json: %v", err)
	}
	if len(infoBytes) == 0 {
		t.Fatalf("container_info.json is empty")
	}
	keyBytes, err := os.ReadFile(filepath.Join(st.Root, "control_pubkey.ed25519"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		t.Fatalf("on-disk public key = %d bytes, want %d", len(keyBytes), ed25519.PublicKeySize)
	}
}

// TestStageRejectsNon32ByteKey is the fail-closed key check: a key that is not
// exactly 32 bytes is refused and nothing is written under the base.
func TestStageRejectsNon32ByteKey(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	s := handoff.NewStager(base)

	for _, n := range []int{0, 31, 33, 64} {
		_, err := s.Stage(context.Background(), "sess-bad", make([]byte, n), nil)
		if !errors.Is(err, handoff.ErrBadPublicKey) {
			t.Fatalf("Stage with %d-byte key: error %v, want ErrBadPublicKey", n, err)
		}
	}

	// Nothing was staged under the base: the per-session root was never created
	// (the key check fails before any filesystem write).
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("base has %d entries after rejected stage, want 0", len(entries))
	}
}

// TestUnstageRemovesTree proves Unstage removes the whole per-session tree.
func TestUnstageRemovesTree(t *testing.T) {
	t.Parallel()
	s := newStager(t)
	st, err := s.Stage(context.Background(), "sess-2", freshPubKey(t), nil)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := s.Unstage(context.Background(), st); err != nil {
		t.Fatalf("Unstage: %v", err)
	}
	if _, err := os.Stat(st.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root still present after Unstage: stat err = %v", err)
	}
}

// TestUnstageIdempotent proves a second Unstage (already-gone root) is satisfied,
// so the create unwind and a later reconcile can both call it.
func TestUnstageIdempotent(t *testing.T) {
	t.Parallel()
	s := newStager(t)
	st, err := s.Stage(context.Background(), "sess-3", freshPubKey(t), nil)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := s.Unstage(context.Background(), st); err != nil {
		t.Fatalf("first Unstage: %v", err)
	}
	if err := s.Unstage(context.Background(), st); err != nil {
		t.Fatalf("second Unstage (idempotent): %v", err)
	}
}

// TestUnstageEmptyRootNoop proves an empty Root is a no-op, so a never-staged
// compensator is safe to run.
func TestUnstageEmptyRootNoop(t *testing.T) {
	t.Parallel()
	s := newStager(t)
	if err := s.Unstage(context.Background(), handoff.Staged{}); err != nil {
		t.Fatalf("Unstage empty Root: %v", err)
	}
}

// TestStageCancelledContextFailsClosed proves a cancelled context refuses the
// stage before any write.
func TestStageCancelledContextFailsClosed(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	s := handoff.NewStager(base)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.Stage(ctx, "sess-cancel", freshPubKey(t), nil); err == nil {
		t.Fatalf("Stage on cancelled ctx: want error, got nil")
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("base has %d entries after cancelled stage, want 0", len(entries))
	}
}

// TestStageMountIntentAccepted proves Stage accepts a mount-intent slice (the
// later-phase mount-material seam) without writing any secret into the handoff.
func TestStageMountIntentAccepted(t *testing.T) {
	t.Parallel()
	s := newStager(t)
	mounts := []runtime.MountIntent{
		{Destination: "/workspace/out", FilesystemID: "fs-1", AuthToken: "placeholder"},
	}
	st, err := s.Stage(context.Background(), "sess-mount", freshPubKey(t), mounts)
	if err != nil {
		t.Fatalf("Stage with mounts: %v", err)
	}
	// The AuthToken is NOT written into any handoff artifact this phase.
	keyBytes, err := os.ReadFile(filepath.Join(st.Root, "control_pubkey.ed25519"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	infoBytes, err := os.ReadFile(filepath.Join(st.Root, "container_info.json"))
	if err != nil {
		t.Fatalf("read container_info.json: %v", err)
	}
	for _, b := range [][]byte{keyBytes, infoBytes} {
		if containsToken(b, "placeholder") {
			t.Fatalf("handoff artifact leaked the mount AuthToken")
		}
	}
}

// containsToken reports whether b contains the literal token bytes.
func containsToken(b []byte, token string) bool {
	return len(token) > 0 && len(b) >= len(token) && indexOf(b, []byte(token)) >= 0
}

// indexOf is a tiny substring search to avoid pulling bytes.Contains into the
// test's mental model; it returns the first index of sub in b or -1.
func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
