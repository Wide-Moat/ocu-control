// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Engine fault-path and pass-through coverage. An adversarial self-audit found
// the Engine's post-audit failure branches (store.Put, store.Revoke, and
// rerender error propagation on both Create and Revoke) had ZERO coverage — the
// only fault the suite injected was an audit-emit fault, and the rerender stub
// always returned nil. It also found the expiresAt pass-through was never
// exercised with a non-nil value, so a mutant that dropped the operator-requested
// expiry (minting non-expiring keys) shipped green. These tests inject a faulting
// store and a faulting rerender to drive each branch through the shipped Engine.
package mcpkey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// faultStore wraps a real RecordStore and, when armed, returns a fixed error from
// Put or Revoke so the Engine's post-audit store-fault branches are reachable.
// Every other method delegates to the inner store, so the Engine still sees a
// working store for the steps a given test does not fault.
type faultStore struct {
	inner     mcpkey.RecordStore
	putErr    error
	revokeErr error
}

func (f *faultStore) Put(ctx context.Context, rec mcpkey.Record) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.inner.Put(ctx, rec)
}

func (f *faultStore) Get(ctx context.Context, keyID string) (mcpkey.Record, error) {
	return f.inner.Get(ctx, keyID)
}

func (f *faultStore) List(ctx context.Context) ([]mcpkey.Record, error) {
	return f.inner.List(ctx)
}

func (f *faultStore) Revoke(ctx context.Context, keyID string) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	return f.inner.Revoke(ctx, keyID)
}

func (f *faultStore) ActiveRecords(ctx context.Context, now time.Time) ([]mcpkey.Record, error) {
	return f.inner.ActiveRecords(ctx, now)
}

// faultRerender returns a rerender callback that always fails with the given
// error, for the rerender-fault branch.
func faultRerender(cause error) func(context.Context) (mcpkey.RenderOutcome, error) {
	return func(context.Context) (mcpkey.RenderOutcome, error) {
		return mcpkey.RenderOutcome{}, cause
	}
}

// TestEngine_Create_ExpiryPassThrough confirms Create carries a non-nil
// expiresAt onto the persisted record. Without this a mutant that ignores the
// operator-requested expiry (minting keys that never expire — an expiry-control
// bypass) would ship green: every other Create test passes nil.
func TestEngine_Create_ExpiryPassThrough(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	want := time.Date(2027, time.March, 4, 5, 6, 7, 0, time.UTC)
	_, rec, err := eng.Create(context.Background(), scope, "tenant-a", "deploy-1", &want)
	if err != nil {
		t.Fatalf("Create with expiry: %v", err)
	}
	if !rec.ExpiresAt.Equal(want) {
		t.Errorf("returned record ExpiresAt = %v, want %v (operator-requested expiry dropped)", rec.ExpiresAt, want)
	}
	// The stored record must also carry it, so a restart/enumeration honours the expiry.
	got, err := store.Get(context.Background(), rec.KeyID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.ExpiresAt.Equal(want) {
		t.Errorf("stored record ExpiresAt = %v, want %v", got.ExpiresAt, want)
	}
}

// TestEngine_Create_NilExpiryStaysNonExpiring is the companion: a nil expiresAt
// mints a non-expiring record (zero ExpiresAt), so the pass-through test above
// pins the actual value rather than any-non-zero.
func TestEngine_Create_NilExpiryStaysNonExpiring(t *testing.T) {
	t.Parallel()
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	_, rec, err := eng.Create(context.Background(), scope, "tenant-a", "deploy-1", nil)
	if err != nil {
		t.Fatalf("Create nil expiry: %v", err)
	}
	if !rec.ExpiresAt.IsZero() {
		t.Errorf("nil expiry produced ExpiresAt = %v, want zero (non-expiring)", rec.ExpiresAt)
	}
}

// TestEngine_Create_StorePutFault confirms a store.Put failure DENIES the create:
// the error is returned, no SecretKey escapes, and the artifact is not
// re-rendered (the audit already emitted — audit-first — but the durable mutation
// failed, so the caller gets nothing).
func TestEngine_Create_StorePutFault(t *testing.T) {
	t.Parallel()
	putErr := errors.New("store put failed")
	store := &faultStore{inner: mcpkey.NewInMemRecordStore(), putErr: putErr}
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	sk, _, err := eng.Create(context.Background(), scope, "tenant-a", "deploy-1", nil)
	if err == nil {
		t.Fatal("Create with a failing store.Put returned nil; want the store error propagated")
	}
	if !errors.Is(err, putErr) {
		t.Errorf("Create error = %v, want it to wrap the store.Put error", err)
	}
	if !sk.IsZero() {
		t.Error("Create returned a non-zero SecretKey on a store fault")
	}
	if rerenderCount != 0 {
		t.Errorf("Create re-rendered %d times on a store fault; want 0 (no publish after a failed persist)", rerenderCount)
	}
}

// TestEngine_Create_RerenderFault confirms a rerender failure on Create is
// propagated (the artifact could not be published), not swallowed.
func TestEngine_Create_RerenderFault(t *testing.T) {
	t.Parallel()
	rerErr := errors.New("rerender failed")
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	eng := newEngine(store, sink, faultRerender(rerErr))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	_, _, err := eng.Create(context.Background(), scope, "tenant-a", "deploy-1", nil)
	if err == nil {
		t.Fatal("Create with a failing rerender returned nil; want the rerender error propagated")
	}
	if !errors.Is(err, rerErr) {
		t.Errorf("Create error = %v, want it to wrap the rerender error", err)
	}
}

// TestEngine_Revoke_StoreRevokeFault confirms a store.Revoke failure is returned
// (the revoke did not take effect durably), not swallowed as a success.
func TestEngine_Revoke_StoreRevokeFault(t *testing.T) {
	t.Parallel()
	revErr := errors.New("store revoke failed")
	inner := mcpkey.NewInMemRecordStore()
	store := &faultStore{inner: inner, revokeErr: revErr}
	sink := audit.NewRecordingFake()
	rerenderCount := 0
	eng := newEngine(store, sink, newFakeRerender(&rerenderCount))

	scope := newAttestedScope("ocu-operator", "uid:1000")
	_, err := eng.Revoke(context.Background(), scope, "some-key-id", "reason")
	if err == nil {
		t.Fatal("Revoke with a failing store.Revoke returned nil; want the store error propagated")
	}
	if !errors.Is(err, revErr) {
		t.Errorf("Revoke error = %v, want it to wrap the store.Revoke error", err)
	}
	if rerenderCount != 0 {
		t.Errorf("Revoke re-rendered %d times on a store fault; want 0", rerenderCount)
	}
}

// TestEngine_Revoke_RerenderFault confirms a rerender failure on Revoke is
// propagated. This is the branch the ≤5-min revoke-propagation budget depends on:
// if a rerender fault were swallowed, the published artifact would still list the
// revoked key with no error surfaced (NFR-SEC-04).
func TestEngine_Revoke_RerenderFault(t *testing.T) {
	t.Parallel()
	rerErr := errors.New("rerender failed")
	store := mcpkey.NewInMemRecordStore()
	sink := audit.NewRecordingFake()
	eng := newEngine(store, sink, faultRerender(rerErr))

	// Seed a live record so the revoke reaches the rerender step (the store
	// Revoke is idempotent, so it succeeds; the fault is at rerender).
	scope := newAttestedScope("ocu-operator", "uid:1000")
	_, rec, err := func() (mcpkey.SecretKey, mcpkey.Record, error) {
		// Use a non-faulting engine to seed, then swap to the faulting rerender.
		seedEng := newEngine(store, audit.NewRecordingFake(), newFakeRerender(new(int)))
		return seedEng.Create(context.Background(), scope, "tenant-a", "deploy-1", nil)
	}()
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	_, revErr := eng.Revoke(context.Background(), scope, rec.KeyID, "reason")
	if revErr == nil {
		t.Fatal("Revoke with a failing rerender returned nil; want the rerender error propagated")
	}
	if !errors.Is(revErr, rerErr) {
		t.Errorf("Revoke error = %v, want it to wrap the rerender error", revErr)
	}
}
