// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	mcpkeypostgres "github.com/Wide-Moat/ocu-control/internal/mcpkey/postgres"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey/mcpkeytest"
)

// dbURLEnv is the environment variable that points the Postgres leg's tests at
// a live database. When it is unset every Postgres test live-skips cleanly, so
// the minimal-shelf build stays green without a running database. Mirror the
// exact discipline of internal/state/postgres/postgres_test.go.
const dbURLEnv = "OCU_TEST_DATABASE_URL"

// schemaSeq makes each isolated schema name unique within a process run.
var schemaSeq atomic.Uint64

// databaseURL returns the live-database URL, or skips the calling test when the
// env var is unset.
func databaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv(dbURLEnv)
	if url == "" {
		t.Skipf("%s unset: skipping the Postgres mcpkey.RecordStore leg (set it to a live database URL to run)", dbURLEnv)
	}
	return url
}

// newSchema creates a fresh, uniquely-named Postgres schema on the live database
// and registers teardown. Mirrors the state/postgres test helper exactly.
func newSchema(t *testing.T, url string) string {
	t.Helper()
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer admin.Close()

	name := fmt.Sprintf("ocu_mcpkey_test_%d", schemaSeq.Add(1))
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", name)); err != nil {
		t.Fatalf("create schema %s: %v", name, err)
	}
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drop, err := pgxpool.New(dropCtx, url)
		if err != nil {
			t.Logf("teardown: connect to drop schema %s: %v", name, err)
			return
		}
		defer drop.Close()
		if _, err := drop.Exec(dropCtx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", name)); err != nil {
			t.Logf("teardown: drop schema %s: %v", name, err)
		}
	})
	return name
}

// openOnSchema opens a Postgres RecordStore pinned to schema. Mirrors the state
// postgres test helper but returns a mcpkey.RecordStore instead of state.Store.
func openOnSchema(t *testing.T, url, schema string) mcpkey.RecordStore {
	t.Helper()
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool on schema %s: %v", schema, err)
	}
	t.Cleanup(pool.Close)

	s, err := mcpkeypostgres.New(ctx, pool)
	if err != nil {
		t.Fatalf("construct RecordStore on schema %s: %v", schema, err)
	}
	return s
}

// TestPostgres_Conformance runs the shared conformance suite against the Postgres
// RecordStore leg. Each subtest provisions a fresh, isolated schema so cases
// never share rows. When OCU_TEST_DATABASE_URL is unset the suite live-skips.
func TestPostgres_Conformance(t *testing.T) {
	url := databaseURL(t)

	mcpkeytest.RunConformance(t, func() mcpkey.RecordStore {
		schema := newSchema(t, url)
		return openOnSchema(t, url, schema)
	})
}

// TestPostgres_CrossRestartDurability proves that a record Put in one store
// instance survives a reconnect: a second store over the same schema reads it
// back. This is the cross-restart durability property the Postgres leg uniquely
// owns (the in-memory leg is process-local by design).
func TestPostgres_CrossRestartDurability(t *testing.T) {
	url := databaseURL(t)
	schema := newSchema(t, url)

	// First store: Put a record.
	s1 := openOnSchema(t, url, schema)
	minter := mcpkey.NewMinter()
	sk, err := minter.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	type fakeClock struct{ t time.Time }
	clk := &fakeClock{time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)}
	_ = clk // suppress unused warning — we'll use it below

	rec, err := mcpkey.NewRecord(sk, "tenant-durable", "deploy-durable", time.Time{}, simpleClock{time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)})
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	if err := s1.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put on s1: %v", err)
	}

	// Second store over the same schema (simulates a reconnect / restart).
	s2 := openOnSchema(t, url, schema)
	got, err := s2.Get(context.Background(), rec.KeyID)
	if err != nil {
		t.Fatalf("Get on s2 (after restart): %v", err)
	}
	if got.KeyID != rec.KeyID {
		t.Errorf("durability: KeyID mismatch after restart: got %q, want %q", got.KeyID, rec.KeyID)
	}
	if got.Tenant != rec.Tenant {
		t.Errorf("durability: Tenant mismatch after restart: got %q, want %q", got.Tenant, rec.Tenant)
	}
	if got.Status != mcpkey.StatusActive {
		t.Errorf("durability: Status after restart: got %q, want %q", got.Status, mcpkey.StatusActive)
	}
}

// simpleClock is a trivial state.Clock for test use.
type simpleClock struct{ t time.Time }

func (c simpleClock) Now() time.Time                  { return c.t }
func (c simpleClock) Since(mark time.Time) time.Duration { return c.t.Sub(mark) }
