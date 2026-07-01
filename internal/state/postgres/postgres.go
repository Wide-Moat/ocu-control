// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package postgres is the Postgres state.Store leg: the durable, cross-restart
// implementation of the persistence seam package state defines. It is the only
// place the pgx driver is imported, so the control plane and the top-level
// state package stay free of any concrete database dependency — control logic
// welds to state.Store, and this subpackage is the one part of the tree that
// knows Postgres exists.
//
// The behavioural contract is identical to the in-memory leg: both pass the one
// shared state.RunConformance suite. The two differ only in mechanism — where
// the in-memory leg serializes a reservation key on a striped sync.Mutex, this
// leg serializes it on a transaction-scoped Postgres advisory lock keyed on the
// same string hash, so the contention surface matches. Where the in-memory leg
// holds its maps in process memory, this leg holds three tables that survive a
// restart, so the durable deny posture and the quota counters reload intact and
// the kill-switch re-engages from durable state before any listener binds.
//
// Every mutator runs its whole body inside one transaction that opens with
// pg_advisory_xact_lock; the lock auto-releases on COMMIT or ROLLBACK, so a
// torn-down request can never leak a held lock. A transient driver failure or a
// cancelled context is wrapped as state.ErrStoreUnavailable — fail-closed
// evidence the admission gate treats as a refusal, never an allow.
package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// pgUniqueViolation is the SQLSTATE a unique-constraint breach raises (the
// "unique_violation" class). The write-once container_name bind relies on the
// partial UNIQUE index as its durable backstop and maps this code to
// state.ErrBindingExists, so two callers racing the same runtime identity
// resolve to exactly one winner without an application-level read-then-write
// window.
const pgUniqueViolation = "23505"

//go:embed schema.sql
var schemaSQL string

// store is the Postgres state.Store. It holds the connection pool and the
// injected Clock; it never calls time.Now directly, so a wall-clock setback
// moves no window the way the seam requires. It is safe for concurrent use
// because the pool is, and because every mutation is serialized per key by a
// Postgres advisory lock rather than by in-process state.
type store struct {
	pool *pgxpool.Pool
	clk  state.Clock
}

// New builds a Postgres state.Store over an existing pool and runs the schema
// migration idempotently, so a fresh deployment is provisioned and an existing
// one is a no-op. It returns state.ErrStoreUnavailable if the migration cannot
// run, so a boot against an unreachable database fails closed rather than
// coming up half-initialized.
func New(ctx context.Context, pool *pgxpool.Pool, clk state.Clock) (state.Store, error) {
	s := &store{pool: pool, clk: clk}
	if err := s.Migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Open is the convenience constructor: it parses url, opens a pool, and hands
// off to New. The caller that built the pool itself should prefer New so it
// owns the pool's lifecycle; Open is for the simple single-owner case. A pool
// opened here is closed again if the migration fails, so a failed Open leaks no
// connections.
func Open(ctx context.Context, url string, clk state.Clock) (state.Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: open pool: %v", state.ErrStoreUnavailable, err)
	}
	s, err := New(ctx, pool, clk)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Migrate applies the embedded schema. Every statement is idempotent — CREATE
// ... IF NOT EXISTS for the tables and indexes, ALTER TABLE ... ADD COLUMN IF
// NOT EXISTS for the additive read-surface columns — so this runs on every boot
// and is safe on a fresh or an existing deployment alike. A transient failure is
// wrapped as state.ErrStoreUnavailable.
func (s *store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("%w: migrate: %v", state.ErrStoreUnavailable, err)
	}
	return nil
}

// unavailable wraps a transient driver failure (or a cancelled context) as the
// fail-closed state.ErrStoreUnavailable sentinel, preserving the cause for
// logs. The sentinel is matchable through errors.Is; the cause is %v and stays
// opaque, matching the repo's wrap idiom.
func unavailable(op string, err error) error {
	return fmt.Errorf("%w: %s: %v", state.ErrStoreUnavailable, op, err)
}

// isUniqueViolation reports whether err is the Postgres unique-violation
// SQLSTATE, the durable backstop the write-once bind maps to ErrBindingExists.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// reservationLockSQL acquires the transaction-scoped advisory lock for the
// reservation domain, keyed on hashtextextended(key) so it partitions on the
// same string hash the in-memory leg stripes on. The lock auto-releases at
// COMMIT/ROLLBACK.
const reservationLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

// quotaLockSQL acquires the transaction-scoped advisory lock for the quota
// domain — a distinct lock space from the reservation domain — keyed on the
// dimension folded together with the billed scope id, so a Charge serializes
// only against another Charge to the same cell and never against a Reserve.
const quotaLockSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

// Reserve writes a RESERVED row for key inside one transaction that opens with
// the reservation advisory lock, checking the deny posture in fail-closed order
// (global kill-switch, then per-session denylist, then live-row double-book)
// before the INSERT. A refusal rolls back, writing no row; the durable primary
// key is the last-line backstop against a double-book the in-transaction check
// could not see.
func (s *store) Reserve(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return state.SessionRow{}, unavailable("reserve: begin", err)
	}
	defer rollback(ctx, tx)

	if _, err := tx.Exec(ctx, reservationLockSQL, key); err != nil {
		return state.SessionRow{}, unavailable("reserve: lock", err)
	}

	// Deny posture is read inside the held lock so no concurrent SetDeny can
	// slip between the check and the insert. Order is fail-closed: global first.
	killed, sessionDenied, err := s.denyPosture(ctx, tx, key)
	if err != nil {
		return state.SessionRow{}, err
	}
	if killed {
		return state.SessionRow{}, state.ErrKillSwitchEngaged
	}
	if sessionDenied {
		return state.SessionRow{}, state.ErrSessionDenied
	}

	// A live row (RESERVED or ACTIVE) is a double-book; a RELEASED tombstone is
	// not live, so a fresh reserve over it is allowed and overwrites the
	// tombstone with a new RESERVED row.
	var existingState int16
	err = tx.QueryRow(ctx, `SELECT state FROM sessions WHERE key = $1`, key).Scan(&existingState)
	switch {
	case err == nil:
		decoded, derr := sessionStateFromDB(existingState)
		if derr != nil {
			return state.SessionRow{}, derr
		}
		if decoded != state.StateReleased {
			return state.SessionRow{}, state.ErrReservationExists
		}
	case errors.Is(err, pgx.ErrNoRows):
		// No row yet: a fresh reserve.
	default:
		return state.SessionRow{}, unavailable("reserve: probe", err)
	}

	now := s.clk.Now()
	row := state.SessionRow{Key: key, Owner: owner, State: state.StateReserved}
	if _, err := tx.Exec(ctx,
		`INSERT INTO sessions (key, owner_tenant, owner_caller, state, container_name, reserved_at)
		 VALUES ($1, $2, $3, $4, NULL, $5)
		 ON CONFLICT (key) DO UPDATE
		     SET owner_tenant = EXCLUDED.owner_tenant,
		         owner_caller = EXCLUDED.owner_caller,
		         state = EXCLUDED.state,
		         container_name = NULL,
		         reserved_at = EXCLUDED.reserved_at,
		         active_at = NULL,
		         caps_cpu_cores = NULL,
		         caps_memory_bytes = NULL,
		         caps_pids_limit = NULL`,
		key, owner.Tenant, owner.Caller, int16(state.StateReserved), now,
	); err != nil {
		// A unique violation here can only be the partial container_name index,
		// which a fresh RESERVED row (container_name NULL) cannot trip; any such
		// error is therefore a transient store fault, not a logical double-book
		// (the double-book is caught by the live-row probe above under the lock).
		return state.SessionRow{}, unavailable("reserve: insert", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return state.SessionRow{}, unavailable("reserve: commit", err)
	}
	return row, nil
}

// denyPosture reads, inside the supplied transaction, whether the global
// kill-switch is engaged and whether key is per-session denylisted. It runs
// under the caller's held advisory lock so the read and the dependent write
// share one critical section.
func (s *store) denyPosture(ctx context.Context, tx pgx.Tx, key string) (killed, sessionDenied bool, err error) {
	if err = tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM denylist WHERE scope = $1 AND key = '')`,
		int16(state.ScopeGlobal),
	).Scan(&killed); err != nil {
		return false, false, unavailable("reserve: deny-global", err)
	}
	if err = tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM denylist WHERE scope = $1 AND key = $2)`,
		int16(state.ScopeSession), key,
	).Scan(&sessionDenied); err != nil {
		return false, false, unavailable("reserve: deny-session", err)
	}
	return killed, sessionDenied, nil
}

// Commit promotes the caller's RESERVED row to ACTIVE under the reservation
// advisory lock. It SELECTs the row FOR UPDATE, verifies the owner and the
// RESERVED precondition, then UPDATEs. An unknown key is ErrReservationNotFound;
// an owner mismatch or a non-RESERVED state is ErrReservationConflict.
func (s *store) Commit(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	return s.transition(ctx, "commit", key, owner, func(row *state.SessionRow) error {
		if row.State != state.StateReserved {
			return state.ErrReservationConflict
		}
		row.State = state.StateActive
		return nil
	})
}

// Release moves the caller's row to the RELEASED tombstone under the
// reservation advisory lock. It NEVER deletes — RELEASED is a visible terminal
// record. It is idempotent against an already-released row (returns the
// terminal row, no error, no double credit). An unknown key is
// ErrReservationNotFound; an owner mismatch is ErrReservationConflict.
func (s *store) Release(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	return s.transition(ctx, "release", key, owner, func(row *state.SessionRow) error {
		if row.State == state.StateReleased {
			// Already terminal: idempotent no-op, no second capacity credit.
			return errIdempotentNoop
		}
		row.State = state.StateReleased
		return nil
	})
}

// errIdempotentNoop is an internal control signal from a transition mutate
// closure meaning "the row is already in the requested terminal state; commit
// nothing and return it as-is with a nil error". It never escapes the package.
var errIdempotentNoop = errors.New("postgres: idempotent no-op")

// transition is the shared SELECT ... FOR UPDATE / verify / UPDATE skeleton for
// Commit and Release. It opens a transaction, takes the reservation advisory
// lock, loads the row FOR UPDATE, verifies the owner (host-derived authority),
// runs mutate to apply the state-machine step, and persists the result. mutate
// returns ErrReservationConflict for an illegal transition, or errIdempotentNoop
// to short-circuit to the current row without a write.
func (s *store) transition(
	ctx context.Context,
	op, key string,
	owner state.Identity,
	mutate func(*state.SessionRow) error,
) (state.SessionRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return state.SessionRow{}, unavailable(op+": begin", err)
	}
	defer rollback(ctx, tx)

	if _, err := tx.Exec(ctx, reservationLockSQL, key); err != nil {
		return state.SessionRow{}, unavailable(op+": lock", err)
	}

	row, err := selectRowForUpdate(ctx, tx, key)
	if err != nil {
		return state.SessionRow{}, wrapSelect(op, err)
	}
	if row.Owner != owner {
		return state.SessionRow{}, state.ErrReservationConflict
	}

	if err := mutate(&row); err != nil {
		if errors.Is(err, errIdempotentNoop) {
			// No write, but the read is part of a committed snapshot; commit so
			// the advisory lock releases cleanly.
			if cErr := tx.Commit(ctx); cErr != nil {
				return state.SessionRow{}, unavailable(op+": commit", cErr)
			}
			return row, nil
		}
		return state.SessionRow{}, err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET state = $2 WHERE key = $1`,
		key, int16(row.State),
	); err != nil {
		return state.SessionRow{}, unavailable(op+": update", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return state.SessionRow{}, unavailable(op+": commit", err)
	}
	return row, nil
}

// BindContainerName records the runtime container identity on the caller's row
// once, under the reservation advisory lock. It is write-once: it refuses with
// ErrBindingExists when the row already carries a name, and the durable partial
// UNIQUE index is the backstop for the cross-row case — a duplicate raises
// SQLSTATE 23505, which maps to ErrBindingExists, so two callers racing one
// runtime identity resolve to exactly one winner. An unknown key is
// ErrReservationNotFound; an owner mismatch is ErrReservationConflict.
func (s *store) BindContainerName(ctx context.Context, key string, owner state.Identity, containerName string) (state.SessionRow, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return state.SessionRow{}, unavailable("bind: begin", err)
	}
	defer rollback(ctx, tx)

	if _, err := tx.Exec(ctx, reservationLockSQL, key); err != nil {
		return state.SessionRow{}, unavailable("bind: lock", err)
	}

	row, err := selectRowForUpdate(ctx, tx, key)
	if err != nil {
		return state.SessionRow{}, wrapSelect("bind", err)
	}
	if row.Owner != owner {
		return state.SessionRow{}, state.ErrReservationConflict
	}
	if row.ContainerName != "" {
		// Write-once on the same row: a rebind is refused before any write.
		return state.SessionRow{}, state.ErrBindingExists
	}

	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET container_name = $2 WHERE key = $1`,
		key, containerName,
	); err != nil {
		if isUniqueViolation(err) {
			// The partial UNIQUE index rejected a name already bound to another
			// row: two sessions can never claim one runtime identity.
			return state.SessionRow{}, state.ErrBindingExists
		}
		return state.SessionRow{}, unavailable("bind: update", err)
	}
	if err := tx.Commit(ctx); err != nil {
		// A unique violation can surface at COMMIT for a deferred constraint; the
		// index here is immediate, so a commit error is a transient fault.
		return state.SessionRow{}, unavailable("bind: commit", err)
	}

	row.ContainerName = containerName
	return row, nil
}

// LookupSession reads the current row for key without the advisory lock, for the
// read paths. It returns ErrReservationNotFound when no row exists.
func (s *store) LookupSession(ctx context.Context, key string) (state.SessionRow, error) {
	row, err := selectRow(ctx, s.pool, key)
	if err != nil {
		return state.SessionRow{}, wrapSelect("lookup", err)
	}
	return row, nil
}

// LiveSessions returns every reservation row currently in StateReserved or
// StateActive — the live set the boot reconciler reclaims from and the
// kill-switch force-kill-every step enumerates. It is the optional
// live-enumeration capability the registry.LiveLister seam type-asserts the Store
// to; the frozen Store interface is not widened by it.
//
// It is a SNAPSHOT read: no advisory lock is taken (per the seam doc — the
// reconciler tolerates a row mutating under it, since a now-RELEASED row it tries
// to reclaim is an idempotent no-op). The SELECT keys on the same SMALLINT state
// codes the rest of this file uses (int16(state.StateReserved) /
// int16(state.StateActive)), so the enumeration shares one state<->column mapping
// with Reserve/Commit/Release and cannot drift from them. Each row is
// materialized through the SAME scanRow column set/order LookupSession uses
// (key, owner_tenant, owner_caller, state, and the COALESCE of container_name to
// the empty string); the durable reserved_at column is not part of the Go
// SessionRow and is not
// selected. A transient driver failure is wrapped state.ErrStoreUnavailable,
// fail-closed, exactly as the other read paths wrap pgx errors.
func (s *store) LiveSessions(ctx context.Context) ([]state.SessionRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, owner_tenant, owner_caller, state, COALESCE(container_name, '')
		 FROM sessions WHERE state IN ($1, $2)`,
		int16(state.StateReserved), int16(state.StateActive))
	if err != nil {
		return nil, unavailable("live-sessions: query", err)
	}
	defer rows.Close()

	live := make([]state.SessionRow, 0)
	for rows.Next() {
		row, serr := scanRow(rows)
		if serr != nil {
			// A row that scans to an out-of-range state, or a transient scan fault,
			// is fail-closed evidence the reconciler must treat as a refusal, never
			// a partial-and-trusted enumeration.
			return nil, unavailable("live-sessions: scan", serr)
		}
		live = append(live, row)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("live-sessions: iterate", err)
	}
	return live, nil
}

// LiveSessionsEnriched returns every live (RESERVED or ACTIVE) row as an
// EnrichedSessionRow — the frozen row plus the additive read-surface columns
// (reserved_at, active_at, the three caps columns) — for the admin read-API
// (registry.EnrichedLister seam). It is the same SNAPSHOT read as LiveSessions
// (no advisory lock), keyed on the same SMALLINT state codes, so the two
// enumerations cannot drift. active_at and the caps columns are NULLABLE: a
// not-yet-activated row scans them to nil, which maps to a nil *time.Time / *Caps
// so the read view distinguishes a RESERVED row from an activated one. A transient
// driver failure wraps state.ErrStoreUnavailable, fail-closed, exactly as
// LiveSessions does.
func (s *store) LiveSessionsEnriched(ctx context.Context) ([]state.EnrichedSessionRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT key, owner_tenant, owner_caller, state, COALESCE(container_name, ''),
		        reserved_at, active_at, caps_cpu_cores, caps_memory_bytes, caps_pids_limit
		 FROM sessions WHERE state IN ($1, $2)`,
		int16(state.StateReserved), int16(state.StateActive))
	if err != nil {
		return nil, unavailable("live-sessions-enriched: query", err)
	}
	defer rows.Close()

	live := make([]state.EnrichedSessionRow, 0)
	for rows.Next() {
		enriched, serr := scanEnrichedRow(rows)
		if serr != nil {
			// A row that scans to an out-of-range state, or a transient scan fault,
			// is fail-closed evidence the read must treat as a refusal, never a
			// partial-and-trusted enumeration.
			return nil, unavailable("live-sessions-enriched: scan", serr)
		}
		live = append(live, enriched)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("live-sessions-enriched: iterate", err)
	}
	return live, nil
}

// RecordActivation stamps the activation instant and the recorded caps onto an
// already-committed (ACTIVE) row, out of band of the frozen Commit
// (registry.ActivationRecorder seam). It is a single idempotent UPDATE keyed on
// the reservation key — re-recording overwrites with the same data. A row that
// does not exist (a fast release before the record lands) updates zero rows and
// is a harmless no-op on the read surface, not an error, mirroring the in-memory
// leg. The caps_pids_limit column is NULL when PidsLimit is nil. A transient
// driver failure wraps state.ErrStoreUnavailable, fail-closed.
func (s *store) RecordActivation(ctx context.Context, key string, caps state.Caps, at time.Time) error {
	var pids *int64
	if caps.PidsLimit != nil {
		p := *caps.PidsLimit
		pids = &p
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE sessions
		    SET active_at = $2,
		        caps_cpu_cores = $3,
		        caps_memory_bytes = $4,
		        caps_pids_limit = $5
		  WHERE key = $1`,
		key, at, caps.CPUCores, caps.MemoryBytes, pids,
	); err != nil {
		return unavailable("record-activation: update", err)
	}
	return nil
}

// SetDeny writes a durable deny entry and engages it immediately. Re-setting an
// already-set scope/key is idempotent: the row is upserted with the new
// operator context. The global kill-switch normalizes its key to empty so it
// occupies one well-known row.
func (s *store) SetDeny(ctx context.Context, entry state.DenyEntry) error {
	if entry.Scope == state.ScopeGlobal {
		entry.Key = ""
	}
	since := entry.Since
	if since.IsZero() {
		since = s.clk.Now()
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO denylist (scope, key, reason, since)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (scope, key) DO UPDATE
		     SET reason = EXCLUDED.reason, since = EXCLUDED.since`,
		int16(entry.Scope), entry.Key, entry.Reason, since,
	); err != nil {
		return unavailable("set-deny", err)
	}
	return nil
}

// ClearDeny removes a durable deny entry by scope and key, lifting it. Clearing
// an absent entry is idempotent (DELETE of zero rows is a no-op).
func (s *store) ClearDeny(ctx context.Context, scope state.DenyScope, key string) error {
	if scope == state.ScopeGlobal {
		key = ""
	}
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM denylist WHERE scope = $1 AND key = $2`,
		int16(scope), key,
	); err != nil {
		return unavailable("clear-deny", err)
	}
	return nil
}

// LoadDeny returns the full durable deny posture for the boot reload. A
// transient failure returns ErrStoreUnavailable, which the boot sequencer
// treats as not-ready so DENY-ALL is never lifted on a half-read.
func (s *store) LoadDeny(ctx context.Context) ([]state.DenyEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT scope, key, reason, since FROM denylist`)
	if err != nil {
		return nil, unavailable("load-deny: query", err)
	}
	defer rows.Close()

	entries := make([]state.DenyEntry, 0)
	for rows.Next() {
		var (
			scope int16
			e     state.DenyEntry
		)
		if err := rows.Scan(&scope, &e.Key, &e.Reason, &e.Since); err != nil {
			return nil, unavailable("load-deny: scan", err)
		}
		decoded, derr := denyScopeFromDB(scope)
		if derr != nil {
			return nil, derr
		}
		e.Scope = decoded
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("load-deny: iterate", err)
	}
	return entries, nil
}

// Charge atomically check-and-increments the counter cell for key under the
// quota advisory lock. The lock domain is distinct from the reservation domain
// and keyed on the dimension folded with the billed scope id. A positive (or
// zero) delta is refused with ErrQuotaExceeded — leaving the cell unchanged —
// when value+delta would exceed limit, INCLUDING the first charge into an absent
// cell: the guarded INSERT and the guarded ON CONFLICT UPDATE both reject an
// over-limit step, so no row is written or updated and the RETURNING is empty. A
// negative delta releases capacity, is never refused, and saturates at zero.
func (s *store) Charge(ctx context.Context, key state.QuotaKey, delta, limit int64) (int64, error) {
	scopeID := quotaScopeID(key)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, unavailable("charge: begin", err)
	}
	defer rollback(ctx, tx)

	if _, err := tx.Exec(ctx, quotaLockSQL, lockToken(key.Dim, scopeID)); err != nil {
		return 0, unavailable("charge: lock", err)
	}

	var value int64
	if delta < 0 {
		// A release of previously charged capacity is never refused and the
		// counter never goes negative: GREATEST clamps the floor at zero.
		err = tx.QueryRow(ctx,
			`INSERT INTO quota_counters (dim, scope_id, value)
			 VALUES ($1, $2, GREATEST($3::bigint, 0))
			 ON CONFLICT (dim, scope_id) DO UPDATE
			     SET value = GREATEST(quota_counters.value + $3::bigint, 0)
			 RETURNING value`,
			int16(key.Dim), scopeID, delta,
		).Scan(&value)
		if err != nil {
			return 0, unavailable("charge: release", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, unavailable("charge: commit", err)
		}
		return value, nil
	}

	// Positive or zero delta: the fresh-cell INSERT is guarded against the limit
	// (the must-fix) by a WHERE on the SELECT source, and the existing-cell
	// branch is guarded by the ON CONFLICT ... WHERE. An over-limit step matches
	// neither, so no row is affected and RETURNING yields no row.
	// $3 (delta) and $4 (limit) are cast to bigint explicitly: a bare SELECT-list
	// parameter is typed `unknown`, but the same parameter also appears in
	// bigint arithmetic below, and without the cast Postgres deduces two
	// inconsistent types for one parameter (SQLSTATE 42P08).
	err = tx.QueryRow(ctx,
		`INSERT INTO quota_counters (dim, scope_id, value)
		 SELECT $1, $2, $3::bigint WHERE $3::bigint <= $4::bigint
		 ON CONFLICT (dim, scope_id) DO UPDATE
		     SET value = quota_counters.value + $3::bigint
		     WHERE quota_counters.value + $3::bigint <= $4::bigint
		 RETURNING value`,
		int16(key.Dim), scopeID, delta, limit,
	).Scan(&value)
	switch {
	case err == nil:
		if err := tx.Commit(ctx); err != nil {
			return 0, unavailable("charge: commit", err)
		}
		return value, nil
	case errors.Is(err, pgx.ErrNoRows):
		// No row written or updated: the step would have crossed the limit. The
		// cell is left exactly as it was (rolled back), and the caller is refused.
		return 0, state.ErrQuotaExceeded
	default:
		return 0, unavailable("charge: apply", err)
	}
}

// ReadQuota returns the current counter value for key without mutating it. An
// absent cell reads as zero. It is a reporting snapshot and must not drive an
// admission decision the caller intends to honor (a Read-then-Charge is a TOCTOU
// race); gate only with the atomic Charge.
func (s *store) ReadQuota(ctx context.Context, key state.QuotaKey) (int64, error) {
	var value int64
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM quota_counters WHERE dim = $1 AND scope_id = $2`,
		int16(key.Dim), quotaScopeID(key),
	).Scan(&value)
	switch {
	case err == nil:
		return value, nil
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	default:
		return 0, unavailable("read-quota", err)
	}
}

// rowScanner is the minimal surface selectRow needs from a pgx.Row, satisfied by
// both a pool QueryRow and a transaction QueryRow.
type rowScanner interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// selectRow reads a session row by key without locking, for the read path.
func selectRow(ctx context.Context, q rowScanner, key string) (state.SessionRow, error) {
	return scanRow(q.QueryRow(ctx,
		`SELECT key, owner_tenant, owner_caller, state, COALESCE(container_name, '')
		 FROM sessions WHERE key = $1`, key))
}

// selectRowForUpdate reads a session row by key under a FOR UPDATE row lock,
// for the mutator path, so the row cannot change between the read and the
// dependent UPDATE within the transaction.
func selectRowForUpdate(ctx context.Context, tx pgx.Tx, key string) (state.SessionRow, error) {
	return scanRow(tx.QueryRow(ctx,
		`SELECT key, owner_tenant, owner_caller, state, COALESCE(container_name, '')
		 FROM sessions WHERE key = $1 FOR UPDATE`, key))
}

// sessionStateFromDB narrows a SMALLINT read back from the sessions table to the
// closed SessionState enum. A value outside the enum is impossible for a row this
// code wrote, so it can only mean a corrupted or foreign-written column; the
// store treats it as a transient fault (fail-closed) rather than silently
// wrapping it into a bogus state, which an unchecked int16->uint8 conversion
// would do (gosec G115).
func sessionStateFromDB(v int16) (state.SessionState, error) {
	if v < int16(state.StateReserved) || v > int16(state.StateReleased) {
		return 0, unavailable("decode session state", fmt.Errorf("out-of-range session state %d", v))
	}
	return state.SessionState(v), nil
}

// denyScopeFromDB narrows a SMALLINT read back from the denylist table to the
// closed DenyScope enum, failing closed on an out-of-range value for the same
// reason as sessionStateFromDB.
func denyScopeFromDB(v int16) (state.DenyScope, error) {
	if v < int16(state.ScopeGlobal) || v > int16(state.ScopeSession) {
		return 0, unavailable("decode deny scope", fmt.Errorf("out-of-range deny scope %d", v))
	}
	return state.DenyScope(v), nil
}

// scanRow materializes a SessionRow from a pgx.Row, mapping the empty result to
// pgx.ErrNoRows for the caller's wrapSelect to translate to
// ErrReservationNotFound.
func scanRow(row pgx.Row) (state.SessionRow, error) {
	var (
		out state.SessionRow
		st  int16
	)
	if err := row.Scan(&out.Key, &out.Owner.Tenant, &out.Owner.Caller, &st, &out.ContainerName); err != nil {
		return state.SessionRow{}, err
	}
	decoded, err := sessionStateFromDB(st)
	if err != nil {
		return state.SessionRow{}, err
	}
	out.State = decoded
	return out, nil
}

// scanEnrichedRow materializes an EnrichedSessionRow: the frozen columns plus the
// additive read-surface columns. reserved_at is NOT NULL; active_at and the caps
// columns are NULLABLE and scan into pointers, so a not-yet-activated row yields a
// nil ActiveAt and a nil Caps. Caps is materialized only when at least one caps
// column is present (an activated row writes all three together, so the cpu-cores
// column presence is the activation witness).
func scanEnrichedRow(row pgx.Row) (state.EnrichedSessionRow, error) {
	var (
		out      state.EnrichedSessionRow
		st       int16
		activeAt *time.Time
		cpuCores *float64
		memBytes *int64
		pids     *int64
	)
	if err := row.Scan(
		&out.Key, &out.Owner.Tenant, &out.Owner.Caller, &st, &out.ContainerName,
		&out.ReservedAt, &activeAt, &cpuCores, &memBytes, &pids,
	); err != nil {
		return state.EnrichedSessionRow{}, err
	}
	decoded, err := sessionStateFromDB(st)
	if err != nil {
		return state.EnrichedSessionRow{}, err
	}
	out.State = decoded
	out.ActiveAt = activeAt
	// The three caps columns are written together at activation; cpu-cores present
	// is the activation witness. A NULL cpu-cores leaves Caps nil (RESERVED or a
	// pre-enrichment row).
	if cpuCores != nil {
		caps := state.Caps{CPUCores: *cpuCores}
		if memBytes != nil {
			caps.MemoryBytes = *memBytes
		}
		caps.PidsLimit = pids
		out.Caps = &caps
	}
	return out, nil
}

// wrapSelect translates a row-read error: a no-rows result is the typed
// ErrReservationNotFound, anything else is a transient store fault.
func wrapSelect(op string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return state.ErrReservationNotFound
	}
	return unavailable(op+": select", err)
}

// rollback rolls back tx on the deferred cleanup path. A rollback after a
// successful Commit is a no-op the driver reports as ErrTxClosed; that and a
// cancelled-context rollback are both expected on the cleanup path and are
// discarded, so the deferred call never masks the method's real return value.
func rollback(ctx context.Context, tx pgx.Tx) {
	_ = tx.Rollback(ctx)
}

// lockToken folds the dimension into the scope id so the quota advisory lock
// keys on hash(dim, scope_id) — the same composite the in-memory leg's quota
// stripe derives — keeping the two legs' quota contention surfaces identical.
// The token is passed to hashtextextended, which rejects a NUL byte, so the
// dimension is joined to the already-NUL-free scope id with a printable
// separator.
func lockToken(dim state.QuotaDim, scopeID string) string {
	return fmt.Sprintf("%d|%s", dim, scopeID)
}

// quotaScopeID derives the billed scope id for a counter cell, matching the
// in-memory leg byte-for-byte (internal/state.quotaScopeID): DimCallerCreateRate
// bills the caller, every other dimension bills the tenant, and the opaque
// window is folded in so distinct windows are distinct cells. The Store does
// zero time math on the window — it is an opaque key segment.
//
// The billed identity is length-prefixed so the encoding is unambiguous for any
// content, and it carries no NUL byte: this string is stored in the scope_id
// text column and hashed for the advisory lock, and Postgres rejects NUL in text
// (SQLSTATE 22021). The format MUST stay identical to the in-memory leg so the
// two implementations key the same cells and pass one shared conformance suite.
func quotaScopeID(key state.QuotaKey) string {
	billed := key.Identity.Tenant
	if key.Dim == state.DimCallerCreateRate {
		billed = key.Identity.Caller
	}
	return fmt.Sprintf("%d|%d:%s|%s", key.Dim, len(billed), billed, key.Window)
}
