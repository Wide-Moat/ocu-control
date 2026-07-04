// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package postgres

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// dropMidStart anchors the FakeClock for the mid-lifecycle-drop case; the exact
// instant is immaterial (the case asserts error narrowing and row state, not time).
var dropMidStart = time.Date(2025, time.May, 6, 7, 8, 9, 0, time.UTC)

// newStoreOnNamedSchema opens a store pinned to a freshly-created, uniquely-named
// schema and returns it alongside a factory that opens ADDITIONAL independent
// stores on the SAME schema. That lets a test drop one store's pool mid-operation
// and then read the durable row through a second, still-live pool — proving the
// mid-lifecycle drop left no half-committed row. The schema is dropped on cleanup.
func newStoreOnNamedSchema(t *testing.T, url string, clk state.Clock) (*store, func(*testing.T) *store) {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("ocu_dropmid_%d", internalSchemaSeq.Add(1))

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", name)); err != nil {
		admin.Close()
		t.Fatalf("create schema %s: %v", name, err)
	}
	admin.Close()
	t.Cleanup(func() {
		dctx := context.Background()
		drop, derr := pgxpool.New(dctx, url)
		if derr != nil {
			t.Logf("teardown: connect to drop schema %s: %v", name, derr)
			return
		}
		defer drop.Close()
		if _, derr := drop.Exec(dctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", name)); derr != nil {
			t.Logf("teardown: drop schema %s: %v", name, derr)
		}
	})

	openOn := func(t *testing.T) *store {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(url)
		if err != nil {
			t.Fatalf("parse config: %v", err)
		}
		if cfg.ConnConfig.RuntimeParams == nil {
			cfg.ConnConfig.RuntimeParams = map[string]string{}
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = name
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("open pool on schema %s: %v", name, err)
		}
		return &store{pool: pool, clk: clk}
	}

	primary := openOn(t)
	if err := primary.Migrate(ctx); err != nil {
		t.Fatalf("migrate on schema %s: %v", name, err)
	}
	return primary, openOn
}

// TestDropMidLifecycle_SurfacesUnavailableAndLeavesNoHalfCommit drives the S7
// boundary: the Postgres pool becomes unreachable PARTWAY THROUGH a lifecycle op.
// The store already covers connect-time failure (TestOpen_UnreachableURL); this
// covers the mid-operation drop, which the uniform wrap() in postgres.go is
// supposed to narrow to ErrStoreUnavailable.
//
// The test reserves a row (RESERVED), closes the pool that store owns to simulate
// the database dropping out mid-lifecycle, then attempts the NEXT step (Commit) on
// the dead pool. That Commit must:
//   - return an error narrowed to state.ErrStoreUnavailable (fail-closed), not a
//     raw pgx error and not a panic; and
//   - leave NO half-committed row — a SECOND, still-live store on the same schema
//     must read the row as still RESERVED (the Commit did not flip it to ACTIVE
//     against a torn write).
//
// Keystone: if the mid-op query's error were not run through wrap() (postgres.go),
// the Commit error would escape as a raw driver error, failing the ErrStoreUnavailable
// assertion — so dropping the wrap on that path reds this test.
func TestDropMidLifecycle_SurfacesUnavailableAndLeavesNoHalfCommit(t *testing.T) {
	t.Parallel()
	url := internalDatabaseURL(t)
	clk := state.NewFakeClock(dropMidStart)
	ctx := context.Background()

	s, openMore := newStoreOnNamedSchema(t, url, clk)
	owner := state.Identity{Tenant: "tenant-drop", Caller: "caller-drop"}
	const key = "drop-mid-key"

	// Step 1 succeeds: the row is RESERVED and durable.
	if _, err := s.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("Reserve before the drop: %v", err)
	}

	// The database drops out mid-lifecycle: close the pool this store owns.
	s.pool.Close()

	// Step 2 on the dead pool must fail closed, narrowed to ErrStoreUnavailable —
	// never a raw driver error and never a panic.
	_, err := s.Commit(ctx, key, owner)
	if err == nil {
		t.Fatal("Commit on a dropped pool returned nil; want a fail-closed error")
	}
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("Commit on a dropped pool = %v; want it narrowed to state.ErrStoreUnavailable (the uniform wrap must fail closed on a mid-op drop)", err)
	}

	// No half-commit: a fresh, live store on the SAME schema must still read the
	// row as RESERVED — the failed Commit did not flip it to ACTIVE.
	s2 := openMore(t)
	t.Cleanup(s2.pool.Close)
	row, lerr := s2.LookupSession(ctx, key)
	if lerr != nil {
		t.Fatalf("LookupSession through a fresh pool after the drop: %v", lerr)
	}
	if row.State != state.StateReserved {
		t.Fatalf("after a Commit that failed on a dropped pool, the row state = %v; want it still RESERVED (no half-committed ACTIVE)", row.State)
	}
}
