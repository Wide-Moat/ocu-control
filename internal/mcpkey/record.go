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

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrUnsalted is returned by NewRecord and NewRecordWithSalt when the supplied
// (or internally generated) salt is empty or all-zero bytes. An unsalted or
// fixed-salt hash exposes the store to a pass-the-hash attack: a store
// disclosure yields the hash directly, without requiring the attacker to know
// the plaintext. NFR-SEC-87 forbids the unsalted hash; this sentinel is the
// compile-time-proof that the guard is not accidentally dropped.
var ErrUnsalted = errors.New("mcpkey: salt must be non-empty and contain at least one non-zero byte")

// saltLen is the required length of a per-key crypto/rand salt in bytes.
// 32 bytes = 256 bits, matching the entropy floor NFR-SEC-87 names.
const saltLen = 32

// keyIDLen is the number of random bytes drawn to produce a key_id. The
// hex encoding of 12 bytes produces a 24-character ID that is short enough
// to embed in logs and audit records without overshadowing other fields.
const keyIDLen = 12

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

// NewRecord is the sole public constructor for a Record. It draws a fresh
// 32-byte salt from crypto/rand, computes key_hash = sha256(salt ‖ secret),
// mints a short random key_id from crypto/rand that is distinct from the
// secret (never derived from it), and stamps created_at from the injected
// Clock. An empty or all-zero salt is rejected with ErrUnsalted (the
// pass-the-hash floor: NFR-SEC-87, T-08-04). The raw secret is read ONLY via
// SecretKey.Reveal inside this function and is NEVER stored on the Record.
//
// expiresAt is optional: a zero time.Time means the key is non-expiring
// (ADR-0027 §Storage).
func NewRecord(sk SecretKey, tenant, deployment string, expiresAt time.Time, clk state.Clock) (Record, error) {
	// Draw a fresh per-key 32-byte salt.
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Record{}, fmt.Errorf("mcpkey: NewRecord: salt read: %w", err)
	}
	return NewRecordWithSalt(sk, salt, tenant, deployment, expiresAt, clk)
}

// NewRecordWithSalt is the constructor used by tests to inject a specific salt
// so the unsalted-rejection invariant can be asserted without going through
// crypto/rand. Production callers must use NewRecord (which draws a fresh salt
// from crypto/rand). The salt must be non-empty and must contain at least one
// non-zero byte; an all-zero salt is rejected with ErrUnsalted.
func NewRecordWithSalt(sk SecretKey, salt []byte, tenant, deployment string, expiresAt time.Time, clk state.Clock) (Record, error) {
	if err := validateSalt(salt); err != nil {
		return Record{}, err
	}

	// Compute the salted hash: sha256(salt ‖ secret). The raw secret is accessed
	// ONLY here through the single Reveal escape hatch and is never stored.
	raw := sk.Reveal()
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(raw))
	keyHash := h.Sum(nil)

	// Mint a short random key_id. It is drawn from crypto/rand separately from
	// the secret so it is structurally independent: the same secret presented
	// twice would still get a distinct key_id. The hex encoding of 12 random
	// bytes produces a 24-character handle — short enough for logs and audit
	// records, long enough to be collision-resistant in any practical deployment.
	idBytes := make([]byte, keyIDLen)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return Record{}, fmt.Errorf("mcpkey: NewRecord: key_id read: %w", err)
	}
	keyID := hex.EncodeToString(idBytes)

	return Record{
		KeyID:      keyID,
		KeyHash:    keyHash,
		Salt:       salt,
		Tenant:     tenant,
		Deployment: deployment,
		ExpiresAt:  expiresAt,
		Status:     StatusActive,
		CreatedAt:  clk.Now(),
	}, nil
}

// validateSalt returns ErrUnsalted if the salt is empty or all-zero bytes.
// The check is intentionally strict: even a single non-zero byte is enough to
// prove the salt is not a fixed or accidentally zeroed value. Production code
// always draws from crypto/rand which is vanishingly unlikely to produce an
// all-zero 32-byte output; this guard catches a refactor that drops the draw or
// fills with zeros.
func validateSalt(salt []byte) error {
	if len(salt) == 0 {
		return ErrUnsalted
	}
	if bytes.Equal(salt, make([]byte, len(salt))) {
		return ErrUnsalted
	}
	return nil
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

// Revoked returns a copy of the Record with Status set to StatusRevoked. It
// does not mutate the receiver. Rotation is always issue-new + revoke-old per
// ADR-0027; no in-place mutation semantics leak out of this helper.
func (r Record) Revoked() Record {
	r.Status = StatusRevoked
	return r
}
