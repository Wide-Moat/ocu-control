// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package postgres is the Postgres mcpkey.RecordStore leg: the durable,
// cross-restart implementation of the mcpkey.RecordStore seam. It is the only
// place pgx is imported for the mcpkey domain, keeping the core mcpkey package
// free of any concrete database dependency — control logic welds to the
// mcpkey.RecordStore interface, and this subpackage is the one part of the tree
// that knows Postgres exists for the MCP key domain.
//
// The behavioural contract is identical to the in-memory leg: both pass the one
// shared mcpkeytest.RunConformance suite. This leg adds cross-restart durability:
// records written in one process are visible to a second store over the same
// schema, so the key set survives a daemon restart.
//
// pgx is already in the module's dependency graph (internal/state/postgres uses
// it). No new external dependency is introduced.
package postgres

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

//go:embed schema.sql
var schemaSQL string

// statusActive and statusRevoked are the integer codes stored in the status
// column, mirroring the mcpkey.Status closed enum. Using small integers keeps
// the column compact and avoids a text comparison in the active-filter WHERE
// clause.
const (
	statusActive  = int16(0)
	statusRevoked = int16(1)
)

// store is the Postgres mcpkey.RecordStore. It holds the connection pool and is
// safe for concurrent use because the pool is. Every method checks the context
// before issuing a database call, so a cancelled context is always
// ErrStoreUnavailable (fail-closed).
type store struct {
	pool *pgxpool.Pool
}

// New builds a Postgres RecordStore over an existing pool and runs the schema
// migration idempotently, so a fresh deployment is provisioned and an existing
// one is a no-op. It returns mcpkey.ErrStoreUnavailable if the migration cannot
// run, so a boot against an unreachable database fails closed rather than coming
// up half-initialized.
func New(ctx context.Context, pool *pgxpool.Pool) (mcpkey.RecordStore, error) {
	s := &store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Open is the convenience constructor: it parses url, opens a pool, and hands
// off to New. The caller that built the pool itself should prefer New so it owns
// the pool's lifecycle. A pool opened here is closed again if the migration
// fails, so a failed Open leaks no connections.
func Open(ctx context.Context, url string) (mcpkey.RecordStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("%w: open pool: %v", mcpkey.ErrStoreUnavailable, err)
	}
	s, err := New(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// migrate applies the embedded schema. It is idempotent — CREATE TABLE IF NOT
// EXISTS — so running it on every boot is safe on a fresh or existing deployment.
func (s *store) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("%w: migrate: %v", mcpkey.ErrStoreUnavailable, err)
	}
	return nil
}

// unavailable wraps a transient driver failure (or a cancelled context) as the
// fail-closed ErrStoreUnavailable sentinel, preserving the cause for logs.
func unavailable(op string, err error) error {
	return fmt.Errorf("%w: %s: %v", mcpkey.ErrStoreUnavailable, op, err)
}

// Put inserts or overwrites the record keyed on rec.KeyID. It uses
// INSERT ... ON CONFLICT DO UPDATE so a second Put with the same key_id
// overwrites the prior record atomically (upsert semantics).
func (s *store) Put(ctx context.Context, rec mcpkey.Record) error {
	if err := ctx.Err(); err != nil {
		return mcpkey.ErrStoreUnavailable
	}
	status := statusFromRecord(rec)
	var expiresAt *time.Time
	if !rec.ExpiresAt.IsZero() {
		t := rec.ExpiresAt
		expiresAt = &t
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO mcp_keys (key_id, key_hash, salt, tenant, deployment, expires_at, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (key_id) DO UPDATE SET
			key_hash   = EXCLUDED.key_hash,
			salt       = EXCLUDED.salt,
			tenant     = EXCLUDED.tenant,
			deployment = EXCLUDED.deployment,
			expires_at = EXCLUDED.expires_at,
			status     = EXCLUDED.status,
			created_at = EXCLUDED.created_at
	`, rec.KeyID, rec.KeyHash, rec.Salt, rec.Tenant, rec.Deployment, expiresAt, status, rec.CreatedAt)
	if err != nil {
		return unavailable("put", err)
	}
	return nil
}

// Get returns the record for keyID, or ErrRecordNotFound when absent.
func (s *store) Get(ctx context.Context, keyID string) (mcpkey.Record, error) {
	if err := ctx.Err(); err != nil {
		return mcpkey.Record{}, mcpkey.ErrStoreUnavailable
	}
	row := s.pool.QueryRow(ctx, `
		SELECT key_id, key_hash, salt, tenant, deployment, expires_at, status, created_at
		FROM mcp_keys WHERE key_id = $1
	`, keyID)
	rec, err := scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return mcpkey.Record{}, mcpkey.ErrRecordNotFound
	}
	if err != nil {
		return mcpkey.Record{}, unavailable("get", err)
	}
	return rec, nil
}

// List returns all stored records. An empty store returns an empty slice and nil.
func (s *store) List(ctx context.Context) ([]mcpkey.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, mcpkey.ErrStoreUnavailable
	}
	rows, err := s.pool.Query(ctx, `
		SELECT key_id, key_hash, salt, tenant, deployment, expires_at, status, created_at
		FROM mcp_keys
	`)
	if err != nil {
		return nil, unavailable("list", err)
	}
	defer rows.Close()
	return collectRows(rows)
}

// Revoke flips the Status of the record to StatusRevoked. It is idempotent:
// updating an absent or already-revoked record is a no-op (no error).
func (s *store) Revoke(ctx context.Context, keyID string) error {
	if err := ctx.Err(); err != nil {
		return mcpkey.ErrStoreUnavailable
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE mcp_keys SET status = $1 WHERE key_id = $2
	`, statusRevoked, keyID)
	if err != nil {
		return unavailable("revoke", err)
	}
	// Not checking rows-affected: updating an absent or already-revoked row is
	// idempotent by the contract.
	return nil
}

// ActiveRecords returns only records for which IsActive(now) is true. It
// evaluates both the status column and the expires_at column in the query so
// the database does the filter, keeping the result set small.
func (s *store) ActiveRecords(ctx context.Context, now time.Time) ([]mcpkey.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, mcpkey.ErrStoreUnavailable
	}
	// The WHERE clause mirrors Record.IsActive(now): status = active AND
	// (expires_at IS NULL OR expires_at > now). Revoked rows (status=1) are
	// excluded. The Go layer re-checks IsActive as a safety net so the in-memory
	// and Postgres legs stay in lock-step on the definition.
	rows, err := s.pool.Query(ctx, `
		SELECT key_id, key_hash, salt, tenant, deployment, expires_at, status, created_at
		FROM mcp_keys
		WHERE status = $1
		  AND (expires_at IS NULL OR expires_at > $2)
	`, statusActive, now)
	if err != nil {
		return nil, unavailable("active_records", err)
	}
	defer rows.Close()
	return collectRows(rows)
}

// scanRow scans one row from a pgx.Row (QueryRow result) into a Record.
func scanRow(row pgx.Row) (mcpkey.Record, error) {
	var (
		keyID      string
		keyHash    []byte
		salt       []byte
		tenant     string
		deployment string
		expiresAt  *time.Time
		status     int16
		createdAt  time.Time
	)
	if err := row.Scan(&keyID, &keyHash, &salt, &tenant, &deployment, &expiresAt, &status, &createdAt); err != nil {
		return mcpkey.Record{}, err
	}
	return buildRecord(keyID, keyHash, salt, tenant, deployment, expiresAt, status, createdAt), nil
}

// collectRows iterates a pgx.Rows result and collects all records.
func collectRows(rows pgx.Rows) ([]mcpkey.Record, error) {
	var out []mcpkey.Record
	for rows.Next() {
		var (
			keyID      string
			keyHash    []byte
			salt       []byte
			tenant     string
			deployment string
			expiresAt  *time.Time
			status     int16
			createdAt  time.Time
		)
		if err := rows.Scan(&keyID, &keyHash, &salt, &tenant, &deployment, &expiresAt, &status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan row: %v", err)
		}
		out = append(out, buildRecord(keyID, keyHash, salt, tenant, deployment, expiresAt, status, createdAt))
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("collect rows", err)
	}
	if out == nil {
		out = []mcpkey.Record{} // never return nil slice on success
	}
	return out, nil
}

// buildRecord constructs a mcpkey.Record from the scanned column values.
func buildRecord(keyID string, keyHash, salt []byte, tenant, deployment string, expiresAt *time.Time, status int16, createdAt time.Time) mcpkey.Record {
	rec := mcpkey.Record{
		KeyID:      keyID,
		KeyHash:    keyHash,
		Salt:       salt,
		Tenant:     tenant,
		Deployment: deployment,
		CreatedAt:  createdAt,
	}
	if expiresAt != nil {
		rec.ExpiresAt = *expiresAt
	}
	if status == statusRevoked {
		rec.Status = mcpkey.StatusRevoked
	} else {
		rec.Status = mcpkey.StatusActive
	}
	return rec
}

// statusFromRecord converts a mcpkey.Status to the integer column code.
func statusFromRecord(rec mcpkey.Record) int16 {
	if rec.Status == mcpkey.StatusRevoked {
		return statusRevoked
	}
	return statusActive
}
