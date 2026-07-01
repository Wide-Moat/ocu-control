// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mcpkeytest provides the shared RecordStore conformance suite.
// Both the in-memory and Postgres RecordStore implementations must pass
// RunConformance, mirroring the discipline in internal/state/statetest.
// A store leg that drifts from the contract will fail the shared suite
// rather than diverging into a private, inconsistent test set.
package mcpkeytest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// conformanceStart is the fixed instant all conformance subtests anchor
// their records on. Using a deterministic time makes assertions on CreatedAt
// reproducible without wall-clock motion.
var conformanceStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// conformanceClock is a trivial deterministic clock for conformance tests.
type conformanceClock struct{ t time.Time }

func (c conformanceClock) Now() time.Time                  { return c.t }
func (c conformanceClock) Since(mark time.Time) time.Duration { return c.t.Sub(mark) }

// minter is the default Minter used across the suite.
var minter = mcpkey.NewMinter()

// newFixtureRecord returns a freshly minted Record for use in conformance subtests.
// Each call draws fresh entropy from crypto/rand, so records are distinct.
func newFixtureRecord(t *testing.T, tenant, deployment string) mcpkey.Record {
	t.Helper()
	sk, err := minter.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	clk := conformanceClock{conformanceStart}
	rec, err := mcpkey.NewRecord(sk, tenant, deployment, time.Time{}, clk)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}
	return rec
}

// newFixtureRecordExpiring returns a Record that expires at expiresAt.
func newFixtureRecordExpiring(t *testing.T, expiresAt time.Time) mcpkey.Record {
	t.Helper()
	sk, err := minter.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	clk := conformanceClock{conformanceStart}
	rec, err := mcpkey.NewRecord(sk, "tenant-exp", "deploy-exp", expiresAt, clk)
	if err != nil {
		t.Fatalf("NewRecord with expiry: %v", err)
	}
	return rec
}

// RunConformance is the single shared functional conformance suite every
// RecordStore implementation must pass. It mirrors the structure of
// internal/state/statetest.RunConformance: each subtest constructs its own
// store via the provided factory so cases never share state. Inputs are
// deterministic (fixed tenant/deployment strings, deterministic clock) except
// for the per-key crypto/rand salt and key_id, which are intentionally random
// to prove the store is robust to arbitrary inputs.
//
// newStore builds a fresh, empty RecordStore for each subtest. The factory is
// called once per subtest, not once per RunConformance call, so subtests are
// hermetic.
func RunConformance(t *testing.T, newStore func() mcpkey.RecordStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("Put then Get returns the stored Record", func(t *testing.T) {
		s := newStore()
		rec := newFixtureRecord(t, "tenant-a", "deploy-1")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(ctx, rec.KeyID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.KeyID != rec.KeyID {
			t.Errorf("Get returned KeyID %q; want %q", got.KeyID, rec.KeyID)
		}
		if got.Tenant != rec.Tenant {
			t.Errorf("Get returned Tenant %q; want %q", got.Tenant, rec.Tenant)
		}
		if got.Status != mcpkey.StatusActive {
			t.Errorf("Get returned Status %q; want %q", got.Status, mcpkey.StatusActive)
		}
	})

	t.Run("Get of an absent key_id returns ErrRecordNotFound", func(t *testing.T) {
		s := newStore()
		_, err := s.Get(ctx, "nonexistent-key-id")
		if !errors.Is(err, mcpkey.ErrRecordNotFound) {
			t.Fatalf("Get absent: want ErrRecordNotFound, got %v", err)
		}
	})

	t.Run("List returns all stored records", func(t *testing.T) {
		s := newStore()
		recs := make([]mcpkey.Record, 3)
		for i := range recs {
			recs[i] = newFixtureRecord(t, "tenant-list", "deploy-list")
			if err := s.Put(ctx, recs[i]); err != nil {
				t.Fatalf("Put #%d: %v", i, err)
			}
		}
		all, err := s.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(all) != len(recs) {
			t.Fatalf("List: want %d records, got %d", len(recs), len(all))
		}
		// Every stored key_id must appear in the list.
		byID := make(map[string]struct{}, len(all))
		for _, r := range all {
			byID[r.KeyID] = struct{}{}
		}
		for _, r := range recs {
			if _, ok := byID[r.KeyID]; !ok {
				t.Errorf("List missing key_id %q", r.KeyID)
			}
		}
	})

	t.Run("List on an empty store returns the empty set, not an error", func(t *testing.T) {
		s := newStore()
		all, err := s.List(ctx)
		if err != nil {
			t.Fatalf("List on empty store: unexpected error %v", err)
		}
		if len(all) != 0 {
			t.Fatalf("List on empty store: want 0 records, got %d", len(all))
		}
	})

	t.Run("Revoke flips status to revoked and a subsequent Get shows revoked", func(t *testing.T) {
		s := newStore()
		rec := newFixtureRecord(t, "tenant-rev", "deploy-rev")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Revoke(ctx, rec.KeyID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		got, err := s.Get(ctx, rec.KeyID)
		if err != nil {
			t.Fatalf("Get after Revoke: %v", err)
		}
		if got.Status != mcpkey.StatusRevoked {
			t.Errorf("Get after Revoke: want StatusRevoked, got %q", got.Status)
		}
	})

	t.Run("Revoke of an absent key is idempotent (no error)", func(t *testing.T) {
		s := newStore()
		// Revoking a key that was never Put is idempotent: no error.
		if err := s.Revoke(ctx, "never-stored-key"); err != nil {
			t.Fatalf("Revoke absent key: want nil error, got %v", err)
		}
	})

	t.Run("Revoke of an already-revoked key is idempotent (no error)", func(t *testing.T) {
		s := newStore()
		rec := newFixtureRecord(t, "t", "d")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Revoke(ctx, rec.KeyID); err != nil {
			t.Fatalf("first Revoke: %v", err)
		}
		// Second Revoke must be idempotent.
		if err := s.Revoke(ctx, rec.KeyID); err != nil {
			t.Fatalf("idempotent Revoke: want nil, got %v", err)
		}
	})

	t.Run("ActiveRecords omits revoked records", func(t *testing.T) {
		s := newStore()
		active := newFixtureRecord(t, "t", "d")
		revoked := newFixtureRecord(t, "t", "d")
		if err := s.Put(ctx, active); err != nil {
			t.Fatalf("Put active: %v", err)
		}
		if err := s.Put(ctx, revoked); err != nil {
			t.Fatalf("Put revoked: %v", err)
		}
		if err := s.Revoke(ctx, revoked.KeyID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		now := conformanceStart.Add(time.Minute)
		results, err := s.ActiveRecords(ctx, now)
		if err != nil {
			t.Fatalf("ActiveRecords: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("ActiveRecords: want 1 active record, got %d", len(results))
		}
		if results[0].KeyID != active.KeyID {
			t.Errorf("ActiveRecords: expected active key_id %q, got %q", active.KeyID, results[0].KeyID)
		}
	})

	t.Run("ActiveRecords omits expired records", func(t *testing.T) {
		s := newStore()
		// Create a record that expires in the past relative to our now.
		expiresAt := conformanceStart.Add(-time.Minute) // already expired
		expired := newFixtureRecordExpiring(t, expiresAt)
		live := newFixtureRecord(t, "t", "d")
		if err := s.Put(ctx, expired); err != nil {
			t.Fatalf("Put expired: %v", err)
		}
		if err := s.Put(ctx, live); err != nil {
			t.Fatalf("Put live: %v", err)
		}
		now := conformanceStart // expired.ExpiresAt is before now
		results, err := s.ActiveRecords(ctx, now)
		if err != nil {
			t.Fatalf("ActiveRecords: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("ActiveRecords: want 1 non-expired record, got %d", len(results))
		}
		if results[0].KeyID != live.KeyID {
			t.Errorf("ActiveRecords: expected live key_id %q, got %q", live.KeyID, results[0].KeyID)
		}
	})

	t.Run("ActiveRecords on empty store returns empty set, not error", func(t *testing.T) {
		s := newStore()
		results, err := s.ActiveRecords(ctx, conformanceStart)
		if err != nil {
			t.Fatalf("ActiveRecords on empty store: unexpected error %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("ActiveRecords on empty store: want 0 records, got %d", len(results))
		}
	})

	t.Run("ActiveRecords with all revoked returns empty set, not error", func(t *testing.T) {
		s := newStore()
		rec := newFixtureRecord(t, "t", "d")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Revoke(ctx, rec.KeyID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		results, err := s.ActiveRecords(ctx, conformanceStart)
		if err != nil {
			t.Fatalf("ActiveRecords with all revoked: unexpected error %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("ActiveRecords with all revoked: want empty set, got %d records", len(results))
		}
	})

	t.Run("Put with duplicate key_id overwrites the existing record", func(t *testing.T) {
		// This tests the store's upsert behavior: a second Put with the same
		// key_id overwrites the prior record. This is the correct behavior for
		// a revoke-then-re-store flow.
		s := newStore()
		rec := newFixtureRecord(t, "t", "d")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("first Put: %v", err)
		}
		// Mutate status and re-put.
		revoked := rec.Revoked()
		if err := s.Put(ctx, revoked); err != nil {
			t.Fatalf("second Put (revoked): %v", err)
		}
		got, err := s.Get(ctx, rec.KeyID)
		if err != nil {
			t.Fatalf("Get after upsert: %v", err)
		}
		if got.Status != mcpkey.StatusRevoked {
			t.Errorf("upserted record: want StatusRevoked, got %q", got.Status)
		}
	})

	t.Run("cancelled context returns ErrStoreUnavailable on all methods", func(t *testing.T) {
		s := newStore()
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()

		rec := newFixtureRecord(t, "t", "d")

		if err := s.Put(cancelled, rec); !errors.Is(err, mcpkey.ErrStoreUnavailable) {
			t.Errorf("Put on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.Get(cancelled, "any"); !errors.Is(err, mcpkey.ErrStoreUnavailable) {
			t.Errorf("Get on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.List(cancelled); !errors.Is(err, mcpkey.ErrStoreUnavailable) {
			t.Errorf("List on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if err := s.Revoke(cancelled, "any"); !errors.Is(err, mcpkey.ErrStoreUnavailable) {
			t.Errorf("Revoke on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.ActiveRecords(cancelled, conformanceStart); !errors.Is(err, mcpkey.ErrStoreUnavailable) {
			t.Errorf("ActiveRecords on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
	})
}
