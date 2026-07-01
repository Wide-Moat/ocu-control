-- SPDX-License-Identifier: FSL-1.1-Apache-2.0
-- Copyright (c) 2025 Open Computer Use Contributors
--
-- Durable schema for the Postgres state.Store leg. Every statement is
-- CREATE ... IF NOT EXISTS so New/Migrate is idempotent and safe to run on
-- every boot: a fresh deployment provisions the tables, an existing one is a
-- no-op. The three tables mirror the three lock domains the interface names —
-- the reservation registry, the durable deny posture, and the quota counters —
-- and the SMALLINT enum columns hold the same closed enumerations the Go
-- SessionState / DenyScope / QuotaDim types pin (the application owns the
-- mapping; the column is a compact tag, not a CHECK-constrained domain).

-- sessions is the reservation registry. key is the host-derived reservation key
-- and the primary key, so the durable PK is the double-book backstop a Reserve
-- relies on under the advisory lock. A RELEASED row stays as a tombstone (state
-- = 2); it is never deleted. container_name is globally unique when present:
-- the partial UNIQUE index treats NULL as distinct (the NULLS-distinct
-- behaviour) so many unbound rows coexist while no two bound rows share one
-- runtime identity — the durable backstop for the write-once bind.
CREATE TABLE IF NOT EXISTS sessions (
    key            TEXT PRIMARY KEY,
    owner_tenant   TEXT NOT NULL,
    owner_caller   TEXT NOT NULL,
    state          SMALLINT NOT NULL,
    container_name TEXT,
    reserved_at    TIMESTAMPTZ NOT NULL
);

-- Read-surface enrichment columns (admin read-API, additive). All four are
-- NULLABLE: they carry the durable resource caps the provider stamped and the
-- RESERVED -> ACTIVE transition instant, neither of which exists on a freshly
-- reserved row, and neither of which the frozen reservation mutators write. They
-- are populated at activation (out of band of the state flip) and read only by
-- the LiveLister enrichment path; the reservation/commit/release contract is
-- unchanged. ADD COLUMN IF NOT EXISTS keeps Migrate idempotent on an existing
-- deployment — a fresh DB gets them from CREATE TABLE-equivalent state, an older
-- one ALTERs them in once.
--   caps_cpu_cores   — runtime.ResourceCaps.CPUCores (fractional cores)
--   caps_memory_bytes— runtime.ResourceCaps.MemoryBytes (hard memory ceiling)
--   caps_pids_limit  — runtime.ResourceCaps.PidsLimit (nil => NULL; no pids cap)
--   active_at        — the RESERVED -> ACTIVE instant; avg-start-time uses
--                      active_at - reserved_at.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS caps_cpu_cores    DOUBLE PRECISION;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS caps_memory_bytes BIGINT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS caps_pids_limit   BIGINT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_at         TIMESTAMPTZ;

-- A partial unique index over the bound rows enforces global container_name
-- uniqueness while leaving unbound (NULL) rows unconstrained. A duplicate bind
-- raises SQLSTATE 23505, which BindContainerName maps to ErrBindingExists.
CREATE UNIQUE INDEX IF NOT EXISTS sessions_container_name_uniq
    ON sessions (container_name)
    WHERE container_name IS NOT NULL;

-- denylist is the durable deny posture, scope-tagged so a restart reload can
-- re-engage each at the right breadth. scope = 0 is the deployment-wide
-- kill-switch (key = ''); scope = 1 is a per-session denylist entry keyed on
-- the reservation key. The composite PK makes a re-set idempotent.
CREATE TABLE IF NOT EXISTS denylist (
    scope  SMALLINT NOT NULL,
    key    TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    since  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, key)
);

-- quota_counters holds the atomic check-and-increment cells. scope_id is the
-- application-derived billed scope (dimension, billed facet, opaque window) so
-- the cell partitioning matches the in-memory leg exactly. value is the running
-- count; the composite PK is the conflict target for the single-statement
-- INSERT ... ON CONFLICT charge.
CREATE TABLE IF NOT EXISTS quota_counters (
    dim      SMALLINT NOT NULL,
    scope_id TEXT NOT NULL,
    value    BIGINT NOT NULL,
    PRIMARY KEY (dim, scope_id)
);
