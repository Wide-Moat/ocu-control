// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtime/docker"
	"github.com/Wide-Moat/ocu-control/internal/state"
	"github.com/Wide-Moat/ocu-control/internal/state/postgres"
)

// TestE2E_CreateDestroy_RealBackends is the milestone capstone for Phase 3: the
// whole lifecycle pipeline driven against a REAL Postgres state.Store AND a REAL
// Docker RuntimeProvider together — no in-memory store, no fake provider. It
// proves that admission → quota → reserve → stage-handoff → materialize → commit →
// bind composes correctly across the two real backends and that destroy tears the
// real container down and tombstones the real row.
//
// It gates on BOTH OCU_TEST_DATABASE_URL (a reachable Postgres) and OCU_RUNTIME_IT=1
// (a reachable Docker daemon); without either it live-skips, so the default
// `go test ./...` stays green everywhere. On a remote daemon (a VM-hosted Docker
// reached over a forwarded socket on a dev laptop) the HOST-01 bind sources are
// resolved by the daemon, so set OCU_RUNTIME_IT_STAGE_DIR to a path visible to both
// this process and the daemon (a shared mount); it defaults to t.TempDir for a
// local daemon (CI).
func TestE2E_CreateDestroy_RealBackends(t *testing.T) {
	dsn := os.Getenv("OCU_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("e2e: OCU_TEST_DATABASE_URL unset (a real Postgres is required) — skipping")
	}
	if os.Getenv("OCU_RUNTIME_IT") != "1" {
		t.Skip("e2e: OCU_RUNTIME_IT=1 unset (a real Docker daemon is required) — skipping")
	}

	ctx := context.Background()
	clk := state.SystemClock()

	// REAL Postgres store. The shared test database accumulates a global
	// kill-switch row across runs (the boot + conformance suites engage it), so
	// clear the global deny posture to give this create→destroy test a clean
	// slate — a stale DENY-ALL is correctly honored by the create path and would
	// otherwise refuse the reserve. This is test hygiene on a shared DB, not a
	// product concern: the kill-switch-first refusal itself is proven elsewhere.
	store, err := postgres.Open(ctx, dsn, clk)
	if err != nil {
		t.Skipf("e2e: Postgres not reachable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = closeStore(store) })
	if err := store.ClearDeny(ctx, state.ScopeGlobal, ""); err != nil {
		t.Fatalf("e2e: clear stale global kill-switch: %v", err)
	}

	// REAL Docker provider at the trusted_operator×runc admit cell.
	provider, err := docker.NewDockerProvider(runtime.TierRunc, docker.Deps{})
	if err != nil {
		t.Fatalf("e2e: NewDockerProvider: %v", err)
	}

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: registry.NewCustodian(store),
		Provider:  provider,
		Clock:     clk,
		// generousLimits is shared with manager_test.go in this package.
		Quota:   quota.NewGate(store, clk, generousLimits()),
		Handoff: handoff.NewStager(e2eStageDir(t)),
		Audit:   audit.NewRecordingFake(),
		Profile: admission.ProfileTrustedOperator,
		Tier:    runtime.TierRunc,
	})

	caller := ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "e2e-tenant", Caller: "e2e-caller"},
		Channel:  ingress.ChannelOperator,
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("e2e: generate key: %v", err)
	}

	pidsLimit := int64(128)
	in := lifecycle.CreateInput{
		Caller:      caller,
		SessionHint: "e2e-session",
		Image:       itImage(),
		Mount: runtime.MountIntent{
			Destination:  "/workspace",
			FilesystemID: "e2e-fs",
			ReadOnly:     false,
			// AuthToken is the Phase-4 weak-JWT placeholder on this path.
			AuthToken:    "phase4-placeholder",
			CacheSeconds: 30,
		},
		Egress: runtime.EgressPolicy{
			DefaultDeny:     true,
			AllowedUpstream: "objectstore.internal",
			FilesystemID:    "e2e-fs",
		},
		Resources: runtime.ResourceCaps{
			CPUCores:    1,
			MemoryBytes: 256 << 20,
			PidsLimit:   &pidsLimit,
		},
		ControlPubKey: pub,
	}

	// CREATE against the real backends.
	row, err := mgr.Create(ctx, in)
	if err != nil {
		t.Fatalf("e2e: Create against real Postgres+Docker: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("e2e: created row state = %v, want ACTIVE", row.State)
	}
	if row.ContainerName == "" {
		t.Fatal("e2e: created row has no bound container_name (BindContainerName did not run)")
	}

	// The row is durable in REAL Postgres: a fresh lookup returns it ACTIVE.
	got, err := store.LookupSession(ctx, row.Key)
	if err != nil {
		t.Fatalf("e2e: durable lookup of the created row: %v", err)
	}
	if got.State != state.StateActive || got.ContainerName != row.ContainerName {
		t.Fatalf("e2e: durable row = {state:%v name:%q}, want {ACTIVE %q}", got.State, got.ContainerName, row.ContainerName)
	}

	// DESTROY: the host-driven finalizer removes the real container and the row is
	// tombstoned RELEASED. Destroy resolves the session from the same host-derived
	// caller + hint, so the body hint is a correlation seed, never the authority.
	if err := mgr.Destroy(ctx, caller, in.SessionHint); err != nil {
		t.Fatalf("e2e: Destroy against real Postgres+Docker: %v", err)
	}

	after, err := store.LookupSession(ctx, row.Key)
	if err != nil {
		t.Fatalf("e2e: post-destroy lookup: %v", err)
	}
	if after.State != state.StateReleased {
		t.Fatalf("e2e: post-destroy row state = %v, want RELEASED (tombstone)", after.State)
	}
}

// e2eStageDir mirrors the docker integration leg's daemon-visible staging: the
// HOST-01 bind sources are resolved by the daemon, so a remote daemon needs a
// shared path. Defaults to t.TempDir for a local daemon.
func e2eStageDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("OCU_RUNTIME_IT_STAGE_DIR")
	if base == "" {
		return t.TempDir()
	}
	dir, err := os.MkdirTemp(base, "ocu-e2e-")
	if err != nil {
		t.Fatalf("e2e: stage dir under OCU_RUNTIME_IT_STAGE_DIR=%q: %v", base, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// itImage is the small image the e2e materializes; overridable for a constrained
// mirror, defaulting to the canonical small busybox the docker leg also uses.
func itImage() string {
	if v := os.Getenv("OCU_RUNTIME_IT_IMAGE"); v != "" {
		return v
	}
	return "busybox:latest"
}

// closeStore best-effort closes a store that exposes an io.Closer-like Close.
func closeStore(s state.Store) error {
	type closer interface{ Close() error }
	if c, ok := s.(closer); ok {
		return c.Close()
	}
	return nil
}
