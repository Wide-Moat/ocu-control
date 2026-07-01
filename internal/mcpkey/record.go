// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mcpkey owns the sk-ocu- credential class: the CSPRNG mint, the
// structurally redacting SecretKey type, the salted-hash Record, the RecordStore
// seam, and the operator Engine. Each piece is a direct composition of an
// existing seam in the control plane.
//
// Plans 08-01 and 08-02 deliver the full mint, record, and store seam.
// This file provides the Record type and Status enum used by the mcpkeyset
// artifact writer (08-03) which runs in the same wave.
package mcpkey

import "time"

// Status is the lifecycle state of a Record. It is a closed enum: only the two
// values below are valid. A revoked record must not appear in any published
// boot-set artifact (fail-closed omission).
type Status string

const (
	// StatusActive is the live state: the key is accepted for validation.
	StatusActive Status = "active"
	// StatusRevoked is the terminal state: the key is rejected; the record is
	// retained for audit but omitted from any published boot-set artifact.
	StatusRevoked Status = "revoked"
)

// Record is the at-rest representation of one MCP API key, locked by
// ADR-0027 §Storage. It holds the salted hash and its binding metadata; it
// NEVER holds the plaintext secret. The same type is serialized for both the
// full-shelf RecordStore and the minimal-shelf hashed-entries file (one type,
// two shelves).
//
// Fields:
//   - KeyID:      the public handle passed to "revoke --id" and used as the
//                 audit actor/correlation field; a short random handle distinct
//                 from the secret (never derived from it — A5).
//   - KeyHash:    sha256(salt ‖ secret); the UNSALTED hash is rejected at
//                 construction (pass-the-hash floor, NFR-SEC-87).
//   - Salt:       a per-key 32-byte crypto/rand salt; stored alongside the hash
//                 so a presented bearer can be re-hashed for comparison.
//   - Tenant:     the tenant the key is scoped to (operator-supplied at issuance).
//   - Deployment: the deployment the key is scoped to.
//   - ExpiresAt:  optional expiry; zero value means non-expiring (ADR-0027).
//   - Status:     active | revoked (closed enum).
//   - CreatedAt:  the instant the record was minted, stamped from the injected
//                 Clock so time math is monotonic-source-safe.
type Record struct {
	KeyID      string    `json:"key_id"`
	KeyHash    []byte    `json:"key_hash"`
	Salt       []byte    `json:"salt"`
	Tenant     string    `json:"tenant"`
	Deployment string    `json:"deployment"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Status     Status    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

// IsExpired reports whether the record has passed its expiry, using the caller's
// now (from a monotonic Clock). A zero ExpiresAt means non-expiring and always
// returns false.
func (r Record) IsExpired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt)
}

// IsActive reports whether the record is active AND not expired. The published
// boot-set artifact includes only records for which IsActive returns true.
func (r Record) IsActive(now time.Time) bool {
	return r.Status == StatusActive && !r.IsExpired(now)
}
