// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// internalDBURLEnv mirrors the env var the black-box suite reads, kept here so
// the internal (white-box) cases live-skip on the same signal: with no live
// database the whole Postgres leg's tests skip cleanly.
const internalDBURLEnv = "OCU_TEST_DATABASE_URL"

// internalSchemaSeq makes each schema this file creates unique within a process
// run, the same isolation discipline the black-box helper uses, so an internal
// case never shares rows with a conformance subtest.
var internalSchemaSeq atomic.Uint64

// internalDatabaseURL returns the live-database URL or skips the calling test
// when the env var is unset, naming the variable so a reader knows what to set.
func internalDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv(internalDBURLEnv)
	if url == "" {
		t.Skipf("%s unset: skipping the Postgres state.Store leg (set it to a live database URL to run)", internalDBURLEnv)
	}
	return url
}

// newInternalStore creates a fresh isolated schema on the live database, opens a
// pool pinned to it, builds the unexported *store directly, and runs the
// migration. It returns the concrete *store so a white-box case can reach the
// pool to inject a corrupt row, plus the live URL for any case that needs it.
// The schema is dropped and the pool closed on test cleanup.
func newInternalStore(t *testing.T, url string, clk state.Clock) *store {
	t.Helper()
	ctx := context.Background()

	name := fmt.Sprintf("ocu_internal_%d", internalSchemaSeq.Add(1))

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
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drop, derr := pgxpool.New(dropCtx, url)
		if derr != nil {
			t.Logf("teardown: connect to drop schema %s: %v", name, derr)
			return
		}
		defer drop.Close()
		if _, derr := drop.Exec(dropCtx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", name)); derr != nil {
			t.Logf("teardown: drop schema %s: %v", name, derr)
		}
	})

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
	t.Cleanup(pool.Close)

	s := &store{pool: pool, clk: clk}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate on schema %s: %v", name, err)
	}
	return s
}

// TestSessionStateFromDB_Valid pins the in-range branch of the SMALLINT→enum
// narrowing for every legal session state: each value the store itself writes
// decodes back to the matching SessionState with no error. This is the path the
// row scanner takes on every healthy read.
func TestSessionStateFromDB_Valid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  int16
		want state.SessionState
	}{
		{int16(state.StateReserved), state.StateReserved},
		{int16(state.StateActive), state.StateActive},
		{int16(state.StateReleased), state.StateReleased},
	}
	for _, c := range cases {
		got, err := sessionStateFromDB(c.raw)
		if err != nil {
			t.Fatalf("sessionStateFromDB(%d): unexpected error %v", c.raw, err)
		}
		if got != c.want {
			t.Fatalf("sessionStateFromDB(%d): want %v, got %v", c.raw, c.want, got)
		}
	}
}

// TestSessionStateFromDB_OutOfRange pins the fail-closed guard: a SMALLINT
// outside the closed SessionState enum can only be a corrupted or foreign-written
// column, so the narrowing refuses it as ErrStoreUnavailable (fail-closed
// evidence the admission gate treats as a refusal) and returns the zero state —
// it never wraps the bad value into a bogus enum. Both an over-range and a
// below-range value are checked so each boundary of the guard is exercised.
func TestSessionStateFromDB_OutOfRange(t *testing.T) {
	t.Parallel()

	for _, raw := range []int16{99, -1} {
		got, err := sessionStateFromDB(raw)
		if !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("sessionStateFromDB(%d): want ErrStoreUnavailable, got %v", raw, err)
		}
		if got != 0 {
			t.Fatalf("sessionStateFromDB(%d): want zero state on failure, got %v", raw, got)
		}
	}
}

// TestDenyScopeFromDB_Valid pins the in-range branch of the deny-scope narrowing
// for every legal scope: the deployment-wide kill-switch (global) and the
// per-session entry both decode back with no error, the path LoadDeny takes per
// reloaded row on a healthy boot.
func TestDenyScopeFromDB_Valid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  int16
		want state.DenyScope
	}{
		{int16(state.ScopeGlobal), state.ScopeGlobal},
		{int16(state.ScopeSession), state.ScopeSession},
	}
	for _, c := range cases {
		got, err := denyScopeFromDB(c.raw)
		if err != nil {
			t.Fatalf("denyScopeFromDB(%d): unexpected error %v", c.raw, err)
		}
		if got != c.want {
			t.Fatalf("denyScopeFromDB(%d): want %v, got %v", c.raw, c.want, got)
		}
	}
}

// TestDenyScopeFromDB_OutOfRange pins the fail-closed guard for the deny-scope
// narrowing: an out-of-range SMALLINT refuses as ErrStoreUnavailable with the
// zero scope, the same fail-closed posture as the session-state guard, so a
// corrupt denylist row fails the boot reload closed rather than re-engaging a
// nonsense scope.
func TestDenyScopeFromDB_OutOfRange(t *testing.T) {
	t.Parallel()

	for _, raw := range []int16{99, -1} {
		got, err := denyScopeFromDB(raw)
		if !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("denyScopeFromDB(%d): want ErrStoreUnavailable, got %v", raw, err)
		}
		if got != 0 {
			t.Fatalf("denyScopeFromDB(%d): want zero scope on failure, got %v", raw, got)
		}
	}
}

// TestQuotaScopeID_BilledFacet pins the durable leg's billed-scope derivation
// directly, the white-box counterpart of the in-memory leg's TestInMemory_BilledFacet:
// the per-caller create-rate dimension bills the caller while every other
// dimension bills the tenant. Both legs must key the same cells for the one
// shared conformance suite to pass on both, so this guards the durable side of
// that equality.
func TestQuotaScopeID_BilledFacet(t *testing.T) {
	t.Parallel()

	id := state.Identity{Tenant: "the-tenant", Caller: "the-caller"}

	createRate := quotaScopeID(state.QuotaKey{Dim: state.DimCallerCreateRate, Identity: id, Window: "w"})
	if !contains(createRate, "the-caller") {
		t.Fatalf("create-rate must bill the caller: scope id %q lacks the caller", createRate)
	}
	if contains(createRate, "the-tenant") {
		t.Fatalf("create-rate must not bill the tenant: scope id %q carries the tenant", createRate)
	}

	for _, dim := range []state.QuotaDim{
		state.DimConcurrentSessions,
		state.DimMCPCallsPerMin,
		state.DimStorageGB,
		state.DimEgressBytesPerDay,
	} {
		scope := quotaScopeID(state.QuotaKey{Dim: dim, Identity: id, Window: "w"})
		if !contains(scope, "the-tenant") {
			t.Fatalf("dim %d must bill the tenant: scope id %q lacks the tenant", dim, scope)
		}
		if contains(scope, "the-caller") {
			t.Fatalf("dim %d must not bill the caller: scope id %q carries the caller", dim, scope)
		}
	}
}

// contains is a tiny substring helper so this file needs no strings import for
// the one place it checks scope-id composition.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestOpen_RoundTrip exercises Open end to end against the live database: it
// parses the URL, opens its own pool, runs the migration, and returns a working
// Store. A Reserve+Lookup round trip proves the returned Store is live, and a
// clean Close proves Open hands back a pool the caller owns. The store is built
// on an isolated schema injected through the URL's search_path option so it does
// not collide with another case's tables.
func TestOpen_RoundTrip(t *testing.T) {
	t.Parallel()

	url := internalDatabaseURL(t)
	ctx := context.Background()
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))

	// Create an isolated schema and route Open's own pool at it via search_path in
	// the URL, so Open's internal pgxpool.New still owns the pool's lifecycle while
	// the tables land in a namespace this case can tear down.
	name := fmt.Sprintf("ocu_open_%d", internalSchemaSeq.Add(1))
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
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		drop, derr := pgxpool.New(dropCtx, url)
		if derr != nil {
			t.Logf("teardown: connect to drop schema %s: %v", name, derr)
			return
		}
		defer drop.Close()
		if _, derr := drop.Exec(dropCtx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", name)); derr != nil {
			t.Logf("teardown: drop schema %s: %v", name, derr)
		}
	})

	openURL := url + "&search_path=" + name

	s, err := Open(ctx, openURL, clk)
	if err != nil {
		t.Fatalf("Open against live database: %v", err)
	}
	if s == nil {
		t.Fatal("Open returned a nil Store with a nil error")
	}

	owner := state.Identity{Tenant: "tenant-a", Caller: "caller-1"}
	if _, err := s.Reserve(ctx, "open-k1", owner); err != nil {
		t.Fatalf("Reserve on the Open'd store: %v", err)
	}
	row, err := s.LookupSession(ctx, "open-k1")
	if err != nil {
		t.Fatalf("LookupSession on the Open'd store: %v", err)
	}
	if row.Key != "open-k1" || row.Owner != owner || row.State != state.StateReserved {
		t.Fatalf("Open round trip: unexpected row %+v", row)
	}

	// The Store Open returns owns its pool; closing it must be clean. The Store
	// interface does not expose Close, so reach the concrete *store to close the
	// pool it opened — the lifecycle Open documents the single-owner caller relies
	// on.
	concrete, ok := s.(*store)
	if !ok {
		t.Fatalf("Open returned a %T, want *store", s)
	}
	concrete.pool.Close()
}

// TestOpen_UnreachableURL pins the error path: Open against an unreachable
// address (a connect-timeout-bounded dial to a closed port) must return a
// non-nil error and a nil Store, leaking no pool. New's migration runs the first
// statement, so the dead address surfaces as ErrStoreUnavailable from either the
// pool open or the migrate, and the convenience constructor cleans up behind
// itself.
func TestOpen_UnreachableURL(t *testing.T) {
	t.Parallel()

	// A reserved-unreachable port with a one-second connect timeout keeps the case
	// fast and hermetic: it needs no live database, only a refused/timed-out dial.
	const deadURL = "postgres://bad:bad@127.0.0.1:1/nope?sslmode=disable&connect_timeout=1"

	ctx := context.Background()
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))

	s, err := Open(ctx, deadURL, clk)
	if err == nil {
		t.Fatal("Open against an unreachable URL: want a non-nil error, got nil")
	}
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("Open against an unreachable URL: want ErrStoreUnavailable, got %v", err)
	}
	if s != nil {
		t.Fatalf("Open against an unreachable URL: want a nil Store, got %T", s)
	}
}

// TestMigrate_Idempotent pins the CREATE ... IF NOT EXISTS path: a second
// Migrate over a store whose schema already exists must succeed as a no-op, the
// property that lets New run the migration on every boot — a fresh deployment is
// provisioned and an existing one is untouched.
func TestMigrate_Idempotent(t *testing.T) {
	t.Parallel()

	url := internalDatabaseURL(t)
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))
	ctx := context.Background()

	s := newInternalStore(t, url, clk)
	// newInternalStore already ran the first migration; a second and third must be
	// no-ops, and a row written between them must survive (the migration touches no
	// data).
	owner := state.Identity{Tenant: "tenant-a", Caller: "caller-1"}
	if _, err := s.Reserve(ctx, "mig-k1", owner); err != nil {
		t.Fatalf("Reserve before re-migrate: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate must be a no-op: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("third Migrate must be a no-op: %v", err)
	}
	row, err := s.LookupSession(ctx, "mig-k1")
	if err != nil {
		t.Fatalf("row must survive a re-migrate: %v", err)
	}
	if row.State != state.StateReserved {
		t.Fatalf("row must survive a re-migrate intact: got state %v", row.State)
	}
}

// TestLookupSession_CorruptRowFailsClosed proves the SMALLINT→enum guard fires on
// a real corrupt row, not only on a direct unit call: a sessions row written
// with an out-of-range state (as a foreign writer or a corruption could leave)
// makes LookupSession refuse with ErrStoreUnavailable rather than surfacing a
// bogus state. The bad row is injected straight through the store's own pool so
// it lands in the same isolated schema the store reads.
func TestLookupSession_CorruptRowFailsClosed(t *testing.T) {
	t.Parallel()

	url := internalDatabaseURL(t)
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))
	ctx := context.Background()

	s := newInternalStore(t, url, clk)

	// Insert a row whose state SMALLINT is outside the closed enum. This is exactly
	// the corruption the narrowing guards against; it cannot be produced through
	// the store's own mutators, so it is written directly.
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (key, owner_tenant, owner_caller, state, container_name, reserved_at)
		 VALUES ($1, $2, $3, $4, NULL, now())`,
		"corrupt-k1", "tenant-a", "caller-1", int16(99),
	); err != nil {
		t.Fatalf("inject corrupt row: %v", err)
	}

	if _, err := s.LookupSession(ctx, "corrupt-k1"); !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("LookupSession over a corrupt row: want ErrStoreUnavailable, got %v", err)
	}
}
