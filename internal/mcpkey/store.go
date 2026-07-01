// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrRecordNotFound is returned by RecordStore.Get when no record addresses
// the given key_id. Callers match with errors.Is.
var ErrRecordNotFound = errors.New("mcpkey: record not found")

// ErrStoreUnavailable wraps a transient backing-store failure (a cancelled
// context, a dropped database connection). It is fail-closed evidence: callers
// treat it as a refusal, never an allow. Callers match with errors.Is.
var ErrStoreUnavailable = errors.New("mcpkey: backing store unavailable")

// RecordStore is the separate persistence seam for MCP API key records. It is
// INTENTIONALLY SEPARATE from internal/state.Store — the frozen Phase-1
// interface is not widened (ADR-0022 EnrichedLister precedent, Q8 HIGH risk).
// A diff that edits internal/state/store.go's Store interface is a plan
// violation; this seam stands beside it, never inside it.
//
// Two implementations satisfy this interface: the in-memory impl (minimal shelf
// default) and the Postgres impl (full shelf, internal/mcpkey/postgres). Both
// pass one shared conformance suite (internal/mcpkey/mcpkeytest.RunConformance).
//
// Method semantics:
//   - Put: insert or overwrite a record keyed on its KeyID.
//   - Get: return the record for the given KeyID, or ErrRecordNotFound.
//   - List: return all records (empty slice is valid, nil error).
//   - Revoke: flip the Status of the record to StatusRevoked; idempotent
//     against an already-revoked or absent key_id (no error).
//   - ActiveRecords: return only records for which IsActive(now) is true;
//     fail-closed on an enumeration fault (never a silent empty set on error).
//
// Every method is context-aware: a cancelled context returns ErrStoreUnavailable
// (fail-closed, never an allow). Implementations are safe for concurrent use.
type RecordStore interface {
	// Put inserts or overwrites a record keyed on rec.KeyID. It is the sole
	// write path for new records; Revoke is the sole path to flip status.
	Put(ctx context.Context, rec Record) error

	// Get returns the record whose KeyID matches keyID. It returns
	// ErrRecordNotFound when no such record exists, and ErrStoreUnavailable
	// on a transient backing-store failure.
	Get(ctx context.Context, keyID string) (Record, error)

	// List returns all stored records. An empty store returns an empty slice
	// and a nil error. ErrStoreUnavailable is returned on a transient failure.
	List(ctx context.Context) ([]Record, error)

	// Revoke flips the Status of the record identified by keyID to
	// StatusRevoked. It is idempotent: revoking an already-revoked or absent
	// key_id returns a nil error. ErrStoreUnavailable is returned on a
	// transient backing-store failure.
	Revoke(ctx context.Context, keyID string) error

	// ActiveRecords returns the subset of records for which IsActive(now) is
	// true — non-revoked AND non-expired. An empty active set returns an empty
	// slice and a nil error (all keys may be expired or revoked). On a
	// transient enumeration fault it returns ErrStoreUnavailable rather than a
	// silent empty set (fail-closed: a publish that cannot enumerate must not
	// silently drop all keys).
	ActiveRecords(ctx context.Context, now time.Time) ([]Record, error)
}

// inMemRecordStore is the in-memory RecordStore implementation. It is the
// minimal-shelf default: zero external dependencies, safe for concurrent use
// via a sync.RWMutex, and the first leg the conformance suite runs against.
// Its contents are lost on process restart; the Postgres impl (full shelf)
// provides cross-restart durability.
type inMemRecordStore struct {
	mu      sync.RWMutex
	records map[string]Record // keyed by KeyID
}

// NewInMemRecordStore returns a fresh, empty in-memory RecordStore. The
// returned store is safe for concurrent use. It satisfies the RecordStore
// seam and passes the mcpkeytest.RunConformance suite.
func NewInMemRecordStore() RecordStore {
	return &inMemRecordStore{
		records: make(map[string]Record),
	}
}

// Put inserts or overwrites the record keyed on rec.KeyID.
func (s *inMemRecordStore) Put(ctx context.Context, rec Record) error {
	if err := ctx.Err(); err != nil {
		return ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.KeyID] = rec
	return nil
}

// Get returns the record for keyID, or ErrRecordNotFound when absent.
func (s *inMemRecordStore) Get(ctx context.Context, keyID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, ErrStoreUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[keyID]
	if !ok {
		return Record{}, ErrRecordNotFound
	}
	return rec, nil
}

// List returns all stored records. An empty store returns an empty slice and
// a nil error.
func (s *inMemRecordStore) List(ctx context.Context) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out, nil
}

// Revoke flips the Status of the record identified by keyID to StatusRevoked.
// It is idempotent: revoking an already-revoked or absent key_id returns nil.
func (s *inMemRecordStore) Revoke(ctx context.Context, keyID string) error {
	if err := ctx.Err(); err != nil {
		return ErrStoreUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[keyID]
	if !ok {
		// Idempotent: revoking an absent key is not an error.
		return nil
	}
	rec.Status = StatusRevoked
	s.records[keyID] = rec
	return nil
}

// ActiveRecords returns only records for which IsActive(now) is true.
func (s *inMemRecordStore) ActiveRecords(ctx context.Context, now time.Time) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, ErrStoreUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Record
	for _, r := range s.records {
		if r.IsActive(now) {
			out = append(out, r)
		}
	}
	if out == nil {
		out = []Record{} // never return nil slice on success
	}
	return out, nil
}
