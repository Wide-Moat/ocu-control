// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package postgres_test

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
	"github.com/Wide-Moat/ocu-control/internal/state/postgres"
	"github.com/Wide-Moat/ocu-control/internal/state/statetest"
)

// dbURLEnv is the environment variable that points the Postgres leg's tests at a
// live database. When it is unset every Postgres test live-skips cleanly, so the
// suite passes in an environment without a reachable Postgres (e.g. CI where the
// container could not be pulled) while still exercising the durable leg wherever
// a database is provided.
const dbURLEnv = "OCU_TEST_DATABASE_URL"

// schemaSeq makes each isolated schema name unique within a process run, so two
// stores built in the same test never collide on the same tables unless they
// are deliberately pointed at the same schema (as the durability cases do).
var schemaSeq atomic.Uint64

// databaseURL returns the live-database URL, or skips the calling test when the
// env var is unset. The skip message names the variable so a reader knows
// exactly what to set to run the durable leg.
func databaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv(dbURLEnv)
	if url == "" {
		t.Skipf("%s unset: skipping the Postgres state.Store leg (set it to a live database URL to run)", dbURLEnv)
	}
	return url
}

// newSchema creates a fresh, uniquely-named Postgres schema on the live database
// and registers its teardown, so each conformance subtest and each durability
// case runs against an isolated namespace and cannot see another case's rows. It
// returns the schema name for a later store to be pinned to.
func newSchema(t *testing.T, url string) string {
	t.Helper()
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer admin.Close()

	// A deterministic-but-unique name: the process-local sequence plus the test
	// name fragment keeps it readable while guaranteeing isolation.
	name := fmt.Sprintf("ocu_test_%d", schemaSeq.Add(1))
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

// openOnSchema builds a Postgres Store whose connections default their
// search_path to the given schema, so the embedded migration provisions its
// tables there and every statement reads and writes that isolated namespace. The
// pool is closed on test cleanup.
func openOnSchema(t *testing.T, url, schema string, clk state.Clock) state.Store {
	t.Helper()
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	// search_path pins every connection in this pool to the isolated schema.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool on schema %s: %v", schema, err)
	}
	t.Cleanup(pool.Close)

	s, err := postgres.New(ctx, pool, clk)
	if err != nil {
		t.Fatalf("construct store on schema %s: %v", schema, err)
	}
	return s
}

// TestPostgres_Conformance runs the one shared Store conformance suite against
// the Postgres leg, so the durable implementation is held to the identical
// behavioural contract the in-memory leg passes. Each subtest's newStore call
// provisions a fresh isolated schema, so cases never share rows. When
// OCU_TEST_DATABASE_URL is unset the whole suite live-skips.
func TestPostgres_Conformance(t *testing.T) {
	url := databaseURL(t)
	statetest.RunConformance(t, func(clk state.Clock) state.Store {
		schema := newSchema(t, url)
		return openOnSchema(t, url, schema, clk)
	})
}

// durOwner is the host-derived identity the durability cases reuse, mirroring
// the conformance suite's fixtures.
var durOwner = state.Identity{Tenant: "tenant-a", Caller: "caller-1"}

// TestPostgres_GlobalKillSwitchSurvivesRestart proves the kill-switch is durable
// across a process restart: store A engages the global kill-switch and is
// closed; store B opened on the SAME schema reloads the posture and refuses a
// fresh Reserve. This is the property the durable leg exists for — the
// kill-switch re-engages from durable state before any listener binds, even on a
// cold boot where no in-process state survived.
func TestPostgres_GlobalKillSwitchSurvivesRestart(t *testing.T) {
	url := databaseURL(t)
	schema := newSchema(t, url)
	ctx := context.Background()
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))

	// Store A engages the deployment-wide kill-switch, then "restarts" (closes).
	a := openOnSchema(t, url, schema, clk)
	if err := a.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal, Reason: "drill"}); err != nil {
		t.Fatalf("A SetDeny global: %v", err)
	}

	// Store B is a fresh boot on the same durable schema: no in-process state
	// carried over, only what survived in Postgres.
	b := openOnSchema(t, url, schema, clk)

	entries, err := b.LoadDeny(ctx)
	if err != nil {
		t.Fatalf("B LoadDeny: %v", err)
	}
	if !hasScope(entries, state.ScopeGlobal, "") {
		t.Fatalf("B LoadDeny after restart: global kill-switch entry missing, got %+v", entries)
	}

	// The reloaded posture is live: a fresh Reserve on B is refused with no row.
	if _, err := b.Reserve(ctx, "k1", durOwner); !errors.Is(err, state.ErrKillSwitchEngaged) {
		t.Fatalf("B Reserve after restart: want ErrKillSwitchEngaged, got %v", err)
	}
	if _, err := b.LookupSession(ctx, "k1"); !errors.Is(err, state.ErrReservationNotFound) {
		t.Fatalf("B refused Reserve must leave no row: want ErrReservationNotFound, got %v", err)
	}
}

// TestPostgres_SessionDenySurvivesRestart proves a per-session denylist entry is
// durable across a restart the same way the global kill-switch is: the denied
// key is still refused on the fresh store, while a sibling key still reserves.
func TestPostgres_SessionDenySurvivesRestart(t *testing.T) {
	url := databaseURL(t)
	schema := newSchema(t, url)
	ctx := context.Background()
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))

	a := openOnSchema(t, url, schema, clk)
	if err := a.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "denied", Reason: "abuse"}); err != nil {
		t.Fatalf("A SetDeny session: %v", err)
	}

	b := openOnSchema(t, url, schema, clk)
	entries, err := b.LoadDeny(ctx)
	if err != nil {
		t.Fatalf("B LoadDeny: %v", err)
	}
	if !hasScope(entries, state.ScopeSession, "denied") {
		t.Fatalf("B LoadDeny after restart: per-session entry missing, got %+v", entries)
	}

	if _, err := b.Reserve(ctx, "denied", durOwner); !errors.Is(err, state.ErrSessionDenied) {
		t.Fatalf("B Reserve denied key after restart: want ErrSessionDenied, got %v", err)
	}
	// A sibling, never denied, still reserves on the fresh store.
	if _, err := b.Reserve(ctx, "allowed", durOwner); err != nil {
		t.Fatalf("B Reserve sibling key after restart: unexpected error %v", err)
	}
}

// TestPostgres_CountersSurviveRestart proves the quota counters are durable: a
// charge committed by store A is still visible to a fresh store B, so a restart
// neither forgets consumed capacity (which would over-admit) nor double-counts
// it.
func TestPostgres_CountersSurviveRestart(t *testing.T) {
	url := databaseURL(t)
	schema := newSchema(t, url)
	ctx := context.Background()
	clk := state.NewFakeClock(time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC))

	a := openOnSchema(t, url, schema, clk)
	key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: durOwner}
	if _, err := a.Charge(ctx, key, 3, 5); err != nil {
		t.Fatalf("A Charge +3: %v", err)
	}

	b := openOnSchema(t, url, schema, clk)
	got, err := b.ReadQuota(ctx, key)
	if err != nil {
		t.Fatalf("B ReadQuota after restart: %v", err)
	}
	if got != 3 {
		t.Fatalf("counter must survive restart: want 3, got %d", got)
	}
	// The surviving count constrains a fresh charge on B: 3 + 3 > 5 is refused,
	// proving the durable value, not a zeroed cell, gates admission after a boot.
	if _, err := b.Charge(ctx, key, 3, 5); !errors.Is(err, state.ErrQuotaExceeded) {
		t.Fatalf("B Charge over surviving count: want ErrQuotaExceeded, got %v", err)
	}
}

// TestPostgres_ClockRollbackMovesNoWindow proves the durable leg reads time only
// through the injected Clock and does zero time math on a window label: moving
// the FakeClock's wall reading backward (an operator or NTP setback) changes
// nothing about which counter cell a charge lands in, because the window is an
// opaque caller-supplied string the Store never derives from a timestamp. A
// per-window counter therefore neither resets nor rolls over on a setback.
func TestPostgres_ClockRollbackMovesNoWindow(t *testing.T) {
	url := databaseURL(t)
	schema := newSchema(t, url)
	ctx := context.Background()

	start := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clk := state.NewFakeClock(start)
	s := openOnSchema(t, url, schema, clk)

	// The admission gate above computes the opaque window label; here it is fixed
	// to a single bucket for the whole test, exactly as it would be within one
	// real window.
	key := state.QuotaKey{Dim: state.DimMCPCallsPerMin, Identity: durOwner, Window: "minute-1"}
	if _, err := s.Charge(ctx, key, 4, 10); err != nil {
		t.Fatalf("Charge before setback: %v", err)
	}

	// A wall-clock setback: move Now backward by an hour. The Store must not
	// react to it at all — no window math consults the wall clock.
	clk.SetWallClock(start.Add(-time.Hour))

	// The same window key still addresses the same cell: the prior count is
	// intact and the next charge accumulates onto it rather than starting fresh.
	v, err := s.Charge(ctx, key, 3, 10)
	if err != nil {
		t.Fatalf("Charge after setback: %v", err)
	}
	if v != 7 {
		t.Fatalf("a wall-clock setback must move no window boundary: want accumulated 7, got %d", v)
	}
	got, err := s.ReadQuota(ctx, key)
	if err != nil {
		t.Fatalf("ReadQuota after setback: %v", err)
	}
	if got != 7 {
		t.Fatalf("the same window cell must hold the accumulated count across a setback: want 7, got %d", got)
	}
}

// TestPostgres_IdleReaperReseedsActiveRowOnBoot is the boot-reseed keystone that
// closes the full-shelf idle-reaper hole. The last-activity stamp the idle reaper
// measures against is held IN PROCESS in no persisted column (a persisted age column
// would reintroduce the NFR-SEC-48 load-then-subtract defect AND turn a clock-jump
// into a fleet-wide mass-reap). So an ACTIVE row that survives a control RESTART has
// no in-process stamp on the fresh process, and without a reseed the reaper — which
// skips a nil-stamp row — would never reclaim it: the slot leaks across every restart,
// exactly on the full shelf where NFR-SEC-40 makes the reaper mandatory.
//
// The fix is a boot-reseed: on construction the store stamps every loaded ACTIVE row's
// in-process last-activity to Clock.Now(), granting each survivor one fresh idle window
// (the honest posture — the true last-activity instant did not survive — and one a
// wall-clock jump cannot move). This activates a session on store A, "restarts" to a
// fresh store B on the same durable schema, and asserts B's enriched enumeration
// carries a NON-NIL LastActivity for the survivor set to the boot instant, so an
// advance past the idle window makes it reapable. Without the reseed the enriched row's
// LastActivity is nil and the survivor is never reaped — this reds.
func TestPostgres_IdleReaperReseedsActiveRowOnBoot(t *testing.T) {
	url := databaseURL(t)
	schema := newSchema(t, url)
	ctx := context.Background()
	bootA := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	clk := state.NewFakeClock(bootA)

	// Store A: create and activate an ACTIVE session, then advance well past an idle
	// window WHILE A is running (A's in-process stamp is live, but it is about to be
	// discarded by the "restart").
	a := openOnSchema(t, url, schema, clk)
	if _, err := a.Reserve(ctx, "k-idle", durOwner); err != nil {
		t.Fatalf("A Reserve: %v", err)
	}
	if _, err := a.Commit(ctx, "k-idle", durOwner); err != nil {
		t.Fatalf("A Commit: %v", err)
	}
	if _, err := a.BindContainerName(ctx, "k-idle", durOwner, "ctr-idle"); err != nil {
		t.Fatalf("A BindContainerName: %v", err)
	}
	// RecordActivation is an optional capability (registry.ActivationRecorder), reached
	// through a type assertion exactly as the lifecycle layer reaches it.
	recorder, ok := a.(interface {
		RecordActivation(context.Context, string, state.Caps, time.Time) error
	})
	if !ok {
		t.Fatal("store A does not satisfy the ActivationRecorder capability")
	}
	if err := recorder.RecordActivation(ctx, "k-idle", state.Caps{CPUCores: 1}, clk.Now()); err != nil {
		t.Fatalf("A RecordActivation: %v", err)
	}

	// The control plane restarts: a fresh store B boots on the SAME durable schema,
	// carrying no in-process activity stamp — only what survived in Postgres (the row,
	// not the stamp). The boot instant advances to bootB.
	bootB := bootA.Add(time.Hour)
	clk.SetWallClock(bootB)
	b := openOnSchema(t, url, schema, clk)

	// B enumerates the enriched live rows: the survivor MUST carry a reseeded
	// LastActivity at the boot instant, not a nil stamp. A nil stamp is the hole —
	// the reaper would skip it forever.
	enriched, err := b.(interface {
		LiveSessionsEnriched(context.Context) ([]state.EnrichedSessionRow, error)
	}).LiveSessionsEnriched(ctx)
	if err != nil {
		t.Fatalf("B LiveSessionsEnriched: %v", err)
	}
	var survivor *state.EnrichedSessionRow
	for i := range enriched {
		if enriched[i].Key == "k-idle" {
			survivor = &enriched[i]
			break
		}
	}
	if survivor == nil {
		t.Fatal("B did not enumerate the surviving ACTIVE row k-idle")
	}
	if survivor.State != state.StateActive {
		t.Fatalf("survivor state = %v, want ACTIVE", survivor.State)
	}
	if survivor.LastActivity == nil {
		t.Fatal("survivor LastActivity is nil after restart — the boot-reseed did not stamp it, so the reaper would skip it forever (slot leaks across restart)")
	}
	if !survivor.LastActivity.Equal(bootB) {
		t.Fatalf("survivor LastActivity = %v, want the boot instant %v (reseeded to Clock.Now() at boot, a fresh window)", *survivor.LastActivity, bootB)
	}

	// The reseeded stamp behaves like a real activity stamp: an advance past the idle
	// window makes the survivor idle by the two-in-process-Clock-reads measure the
	// reaper uses (Clock.Now() minus the stamp), so it becomes reapable — proving the
	// reseed did not merely set a field but restored the row to the reaper's view.
	const idleTTL = 15 * time.Minute
	clk.SetWallClock(bootB.Add(idleTTL + time.Minute))
	if clk.Now().Sub(*survivor.LastActivity) <= idleTTL {
		t.Fatalf("after advancing past the window the reseeded survivor is not idle: now-stamp = %v, want > %v", clk.Now().Sub(*survivor.LastActivity), idleTTL)
	}
}

// hasScope reports whether a loaded deny set contains an entry with the given
// scope and key, so a durability case can assert membership without depending on
// slice order.
func hasScope(entries []state.DenyEntry, scope state.DenyScope, key string) bool {
	for _, e := range entries {
		if e.Scope == scope && e.Key == key {
			return true
		}
	}
	return false
}
