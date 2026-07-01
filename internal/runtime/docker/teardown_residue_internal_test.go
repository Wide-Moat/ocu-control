// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestScrubHandoffRootResidueIsError proves the STRICT zero-residue contract's
// failure leg deterministically: when the recursive removal "succeeds" but the path
// SURVIVES (the TOCTOU race a real concurrent writer could cause), the post-removal
// re-stat catches the surviving credential tree and scrubHandoffRoot returns a
// teardown error rather than swallowing it. The race is injected through the
// removeAll package var — a remover that reports success without removing — since a
// real race is not deterministically reproducible.
func TestScrubHandoffRootResidueIsError(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "sess-x")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("stage residual root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "mount-config.json"), []byte("eyJ.jwt.sig"), 0o600); err != nil {
		t.Fatalf("stage residual credential: %v", err)
	}

	// Inject a remover that LIES: it returns nil but leaves the tree on disk, so the
	// re-stat finds the residual credential present. Not parallel: it mutates a
	// package var.
	orig := removeAll
	removeAll = func(string) error { return nil }
	t.Cleanup(func() { removeAll = orig })

	err := scrubHandoffRoot(root)
	if err == nil {
		t.Fatal("scrubHandoffRoot must report a residual credential tree as a teardown error, got nil")
	}
	if !errors.Is(err, runtime.ErrTeardown) {
		t.Fatalf("residue error must wrap runtime.ErrTeardown, got %v", err)
	}
}

// TestScrubHandoffRootRemoveErrorSurfaces proves a removal fault (not a residue) is
// surfaced too: a remover that returns an error makes scrubHandoffRoot return that
// error, so a real os.RemoveAll failure is never silently swallowed.
func TestScrubHandoffRootRemoveErrorSurfaces(t *testing.T) {
	injected := errors.New("injected remove fault")
	orig := removeAll
	removeAll = func(string) error { return injected }
	t.Cleanup(func() { removeAll = orig })

	err := scrubHandoffRoot("/whatever/root")
	if !errors.Is(err, injected) {
		t.Fatalf("scrubHandoffRoot must surface a removal fault, got %v", err)
	}
}

// TestFinalizeCollectsResidueErrorWithoutShortCircuit proves the residue error is
// COLLECTED into the finalizer's errors.Join and does NOT short-circuit the ordered
// finalizer: even with step 3 failing on a residual handoff tree, the authoritative
// kill (step 5) still runs, and the joined result wraps ErrTeardown. A scrub failure
// is reported but never undoes the authoritative kill.
func TestFinalizeCollectsResidueErrorWithoutShortCircuit(t *testing.T) {
	base := t.TempDir()
	const name = runtime.SessionName("sess-join")
	root := filepath.Join(base, string(name))
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("stage root: %v", err)
	}

	// removeAll lies (succeeds without removing) so step 3 hits the residue branch.
	orig := removeAll
	removeAll = func(string) error { return nil }
	t.Cleanup(func() { removeAll = orig })

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, StagerBase: base})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      name,
		RuntimeID: "ctr-join",
		Egress:    runtime.EgressBinding{Name: name, FilesystemID: "fs-1"},
		Tier:      runtime.TierRunc,
	}

	ferr := p.Teardown().ForceKill(context.Background(), sess)
	if ferr == nil {
		t.Fatal("finalize must surface the step-3 residue error, got nil")
	}
	if !errors.Is(ferr, runtime.ErrTeardown) {
		t.Fatalf("finalize error must wrap runtime.ErrTeardown, got %v", ferr)
	}
	// The authoritative kill (step 5) still ran despite the step-3 failure: the
	// finalizer never short-circuits.
	if fake.countOp("ContainerRemove") == 0 {
		t.Fatal("finalize must still force-remove the container (step 5) despite the step-3 scrub failure")
	}
}
