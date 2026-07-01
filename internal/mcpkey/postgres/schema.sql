-- SPDX-License-Identifier: FSL-1.1-Apache-2.0
-- Copyright (c) 2025 Open Computer Use Contributors
--
-- Durable schema for the Postgres mcpkey.RecordStore leg. Every statement is
-- CREATE ... IF NOT EXISTS so New/Migrate is idempotent and safe to run on
-- every boot: a fresh deployment provisions the table, an existing one is a
-- no-op. The table holds the at-rest MCP API key records locked by ADR-0027.
-- It never holds the plaintext secret — only key_hash + salt + binding metadata.

-- mcp_keys is the at-rest MCP API key record table. key_id is the operator-
-- facing public handle (the "revoke --id" target and the audit correlation
-- field); it is a short random hex string distinct from the secret, never
-- derived from it (A5). key_hash and salt are the salted SHA-256 credential;
-- status is the lifecycle state (active=0, revoked=1). expires_at is NULL when
-- non-expiring (ADR-0027: absent ⇒ non-expiring). created_at is stamped at
-- record construction from the injected Clock.
CREATE TABLE IF NOT EXISTS mcp_keys (
    key_id      TEXT        PRIMARY KEY,
    key_hash    BYTEA       NOT NULL,
    salt        BYTEA       NOT NULL,
    tenant      TEXT        NOT NULL,
    deployment  TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ,
    status      SMALLINT    NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL
);
