// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mcpkeytest provides the shared RecordStore conformance suite.
// Both the in-memory and Postgres RecordStore implementations must pass
// RunConformance, mirroring the discipline in internal/state/statetest.
// A store leg that drifts from the contract will fail the shared suite
// rather than diverging into a private, inconsistent test set.
package mcpkeytest

import (
	"bytes"
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

func (c conformanceClock) Now() time.Time                     { return c.t }
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

	t.Run("Put then Get round-trips EVERY field", func(t *testing.T) {
		s := newStore()
		rec := newFixtureRecord(t, "tenant-a", "deploy-1")
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(ctx, rec.KeyID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		// Round-trip fidelity of EVERY field, not just the handle. KeyHash and
		// Salt are the security-critical bytes: a store that truncates them or
		// swaps their two columns (a real Postgres scanRow hazard) would keep
		// KeyID/Tenant/Status intact and pass a partial check, but the gateway
		// would then hash-compare against corrupted material. bytes.Equal on both
		// catches that.
		assertRecordEqual(t, got, rec)
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

	t.Run("ActiveRecords treats a key expiring EXACTLY at now as inactive", func(t *testing.T) {
		// The expiry-instant boundary: a record whose ExpiresAt is exactly the
		// query's now must be OMITTED (a key at its expiry moment no longer
		// validates). This case pins the boundary on BOTH legs so the in-memory
		// Go path (Record.IsExpired) and the Postgres SQL path (`expires_at > now`)
		// cannot drift by one tick — the divergence an earlier comment falsely
		// claimed a Go-side re-check prevented.
		s := newStore()
		atBoundary := newFixtureRecordExpiring(t, conformanceStart)
		live := newFixtureRecord(t, "t", "d")
		if err := s.Put(ctx, atBoundary); err != nil {
			t.Fatalf("Put at-boundary: %v", err)
		}
		if err := s.Put(ctx, live); err != nil {
			t.Fatalf("Put live: %v", err)
		}
		results, err := s.ActiveRecords(ctx, conformanceStart) // now == atBoundary.ExpiresAt
		if err != nil {
			t.Fatalf("ActiveRecords: %v", err)
		}
		if len(results) != 1 {
			t.Fatalf("ActiveRecords at the expiry instant: want 1 (the at-boundary key omitted), got %d", len(results))
		}
		if results[0].KeyID != live.KeyID {
			t.Errorf("ActiveRecords: a key expiring exactly at now was NOT omitted; got key_id %q, want the live key %q", results[0].KeyID, live.KeyID)
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

	t.Run("Put then Get round-trips an EXPIRING record's ExpiresAt and bytes", func(t *testing.T) {
		s := newStore()
		expiresAt := conformanceStart.Add(720 * time.Hour)
		rec := newFixtureRecordExpiring(t, expiresAt)
		if err := s.Put(ctx, rec); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(ctx, rec.KeyID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		// The store must preserve ExpiresAt (a store that dropped it would turn an
		// expiring key non-expiring — a silent expiry-control bypass) along with
		// the security-critical KeyHash/Salt bytes.
		assertRecordEqual(t, got, rec)
		if got.ExpiresAt.IsZero() {
			t.Error("Get dropped ExpiresAt: an expiring record round-tripped as non-expiring")
		}
	})
}

// assertRecordEqual fails t if got does not match want field-for-field, INCLUDING
// the security-critical KeyHash and Salt byte slices (bytes.Equal) and the
// timestamps (compared by .Equal so a monotonic-clock reading or a UTC/local
// representation difference does not cause a spurious mismatch). It is the shared
// round-trip-fidelity assertion the conformance suite uses so every store leg is
// held to the SAME field-preservation contract — a leg that truncates a hash or
// swaps the key_hash/salt columns fails here rather than shipping green.
func assertRecordEqual(t *testing.T, got, want mcpkey.Record) {
	t.Helper()
	if got.KeyID != want.KeyID {
		t.Errorf("KeyID = %q, want %q", got.KeyID, want.KeyID)
	}
	if !bytes.Equal(got.KeyHash, want.KeyHash) {
		t.Errorf("KeyHash = %x, want %x (security-critical: a corrupted hash breaks gateway validation)", got.KeyHash, want.KeyHash)
	}
	if !bytes.Equal(got.Salt, want.Salt) {
		t.Errorf("Salt = %x, want %x (security-critical: a corrupted salt breaks gateway validation)", got.Salt, want.Salt)
	}
	if got.Tenant != want.Tenant {
		t.Errorf("Tenant = %q, want %q", got.Tenant, want.Tenant)
	}
	if got.Deployment != want.Deployment {
		t.Errorf("Deployment = %q, want %q", got.Deployment, want.Deployment)
	}
	if got.Status != want.Status {
		t.Errorf("Status = %q, want %q", got.Status, want.Status)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}
