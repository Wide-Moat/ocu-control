// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// stageHandoffRoot writes a realistic per-session handoff tree under base, mirroring
// what the create-path stager + mount-config pusher leave on host disk at teardown
// time: the 0700 per-session root, container_info.json, the raw Ed25519 public key,
// the 0700 sock dir, and — the load-bearing part — a JWT-bearing mount-config.json.
// It returns the per-session root so a test can assert it is scrubbed to zero
// residue. The path layout is base/<name>/... exactly as handoff.Stager builds it,
// so finalizer step 3 re-derives the same root purely from the SessionName.
func stageHandoffRoot(t *testing.T, base string, name runtime.SessionName) string {
	t.Helper()
	root := filepath.Join(base, string(name))
	if err := os.MkdirAll(filepath.Join(root, "sock"), 0o700); err != nil {
		t.Fatalf("stage handoff root: %v", err)
	}
	// A REAL JWT-bearing mount-config: a compact three-segment token in the rendered
	// mount-config is exactly the weak Storage-JWT the scrub must not leave behind.
	mountCfg := []byte(`{"token":"eyJhbGciOiJFZERTQSJ9.eyJmaWxlc3lzdGVtX2lkIjoiZnMtMSJ9.c2lnbmF0dXJl","service_url":"https://filestore.example"}`)
	files := map[string][]byte{
		"container_info.json":     []byte(`{"schema":"v1alpha","session_name":"` + string(name) + `","sock_dir":"/run/ocu"}`),
		"control_pubkey.ed25519":  make([]byte, 32),
		"mount-config.json":       mountCfg,
		"sock/exec.sock.metadata": []byte("placeholder"),
	}
	for rel, data := range files {
		if err := os.WriteFile(filepath.Join(root, rel), data, 0o600); err != nil {
			t.Fatalf("stage handoff file %q: %v", rel, err)
		}
	}
	return root
}

// TestTeardownStep3ScrubsHandoffRoot is the non-vacuous step-3 proof: a finalizer
// run over a Sandbox whose handoff root holds a REAL JWT-bearing mount-config (plus
// container_info.json and the 0700 sock dir) scrubs the whole tree to zero residue,
// and a SECOND run over the already-removed root is a clean idempotent no-op. The
// scrub is wired INTO the ordered finalizer (step 3, NFR-SEC-65), so it inherits the
// host-driven/ordered/idempotent guarantees of finalize() — it is not a separate
// best-effort cleanup.
func TestTeardownStep3ScrubsHandoffRoot(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	const name = runtime.SessionName("sess-scrub")
	root := stageHandoffRoot(t, base, name)

	// Sanity: the credential-bearing tree is on disk before the finalizer runs.
	if _, err := os.Stat(filepath.Join(root, "mount-config.json")); err != nil {
		t.Fatalf("precondition: JWT-bearing mount-config must exist before teardown: %v", err)
	}

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, StagerBase: base})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      name,
		RuntimeID: "ctr-scrub",
		Egress:    runtime.EgressBinding{Name: name, FilesystemID: "fs-1"},
		Tier:      runtime.TierRunc,
	}

	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill: %v", err)
	}

	// The whole per-session root is GONE: the credential-bearing files do not outlive
	// the session on host disk.
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("handoff root must be removed after step 3 (stat err=%v); want not-exist", err)
	}
	// And the parent (the stager base) holds NO residue for this session.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("read base dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == string(name) {
			t.Fatalf("stager base still holds the per-session root %q after the scrub", e.Name())
		}
	}

	// A SECOND finalizer run over the already-removed root is a satisfied no-op: the
	// scrub is idempotent (os.RemoveAll on an absent path succeeds, and the re-stat
	// confirms zero residue), so a re-run never errors.
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("idempotent ForceKill re-run over the already-scrubbed root: %v", err)
	}
}

// TestTeardownStep3GracefulStopScrubs proves the scrub runs on the GracefulStop verb
// too (both verbs share one finalize body), so a cooperative Destroy reclaims the
// host-owned credential tree exactly as a force-kill does.
func TestTeardownStep3GracefulStopScrubs(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	const name = runtime.SessionName("sess-graceful-scrub")
	root := stageHandoffRoot(t, base, name)

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, StagerBase: base})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      name,
		RuntimeID: "ctr-graceful-scrub",
		Egress:    runtime.EgressBinding{Name: name, FilesystemID: "fs-1"},
		Tier:      runtime.TierRunc,
	}

	if err := p.Teardown().GracefulStop(context.Background(), sess, runtime.Duration(2)); err != nil {
		t.Fatalf("GracefulStop: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("GracefulStop must scrub the handoff root (stat err=%v); want not-exist", err)
	}
}

// TestTeardownStep3AbsentRootIsNoOp proves the scrub on a never-staged session (no
// handoff root ever created) is a satisfied no-op, not an error — the absent-root
// input state is handled exactly like the already-removed one.
func TestTeardownStep3AbsentRootIsNoOp(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, StagerBase: base})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      runtime.SessionName("sess-never-staged"),
		RuntimeID: "ctr-x",
		Egress:    runtime.EgressBinding{Name: runtime.SessionName("sess-never-staged"), FilesystemID: "fs-1"},
		Tier:      runtime.TierRunc,
	}
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill over an absent handoff root must be a satisfied no-op, got: %v", err)
	}
}

// TestTeardownStep3NoStagerBaseIsNoOp proves the minimal-shelf posture: with no
// stager base wired into the provider, step 3 is a host-side no-op that touches no
// filesystem (mirroring how a nil revoker leaves step 1 a no-op). A handoff tree
// under some OTHER base is left untouched, since the provider scrubs only its own
// deployment-fixed base/<name>.
func TestTeardownStep3NoStagerBaseIsNoOp(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	const name = runtime.SessionName("sess-no-base")
	root := stageHandoffRoot(t, base, name)

	fake := newFakeAPI()
	// No StagerBase: the provider has no handoff base to derive a root from.
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      name,
		RuntimeID: "ctr-no-base",
		Egress:    runtime.EgressBinding{Name: name, FilesystemID: "fs-1"},
		Tier:      runtime.TierRunc,
	}
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("ForceKill with no stager base: %v", err)
	}
	// The tree under the unrelated base is untouched: the no-base provider scrubs
	// nothing, so it cannot reach a path it was never told about.
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("a no-stager-base provider must not touch an unrelated handoff tree: %v", err)
	}
}

// TestTeardownStep3ReScrubOfReCreatedTree proves the verification is re-run every
// finalize, not a one-shot: a tree re-created after a first clean scrub (a writer
// racing a later boot's reconcile) is scrubbed again to zero residue. This exercises
// the present-then-absent re-stat outcome twice, confirming the satisfied state is
// recomputed each run.
func TestTeardownStep3ReScrubOfReCreatedTree(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	const name = runtime.SessionName("sess-rescrub")
	root := filepath.Join(base, string(name))

	fake := newFakeAPI()
	p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake, StagerBase: base})
	if err != nil {
		t.Fatalf("NewDockerProvider: %v", err)
	}
	sess := runtime.Sandbox{
		Name:      name,
		RuntimeID: "ctr-rescrub",
		Egress:    runtime.EgressBinding{Name: name, FilesystemID: "fs-1"},
		Tier:      runtime.TierRunc,
	}

	stageHandoffRoot(t, base, name)
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("first scrub of a real tree must succeed: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("after the first scrub the root must be absent: %v", err)
	}

	stageHandoffRoot(t, base, name)
	if err := p.Teardown().ForceKill(context.Background(), sess); err != nil {
		t.Fatalf("second scrub of a re-created tree must succeed: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("after the second scrub the root must be absent: %v", err)
	}
}
