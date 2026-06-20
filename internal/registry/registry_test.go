// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package registry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// regStart anchors the FakeClock for the registry tests; no case here depends on
// wall-clock motion.
var regStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// newCustodian builds a Custodian over a fresh in-memory Store.
func newCustodian(t *testing.T) (*registry.Custodian, state.Store) {
	t.Helper()
	store := state.NewInMemory(state.NewFakeClock(regStart))
	return registry.NewCustodian(store), store
}

// TestDeriveKeyDeterministic proves the same (owner, handle) yields the same Key,
// so a derived key is stable across calls (a destroy can re-derive a create's key).
func TestDeriveKeyDeterministic(t *testing.T) {
	t.Parallel()
	owner := state.Identity{Tenant: "t1", Caller: "c1"}
	k1 := registry.DeriveKey(owner, "handle-abc")
	k2 := registry.DeriveKey(owner, "handle-abc")
	if k1 != k2 {
		t.Fatalf("DeriveKey not deterministic: %q != %q", k1.String(), k2.String())
	}
	if k1.IsZero() {
		t.Fatalf("DeriveKey produced the zero Key")
	}
	if k1.String() == "" {
		t.Fatalf("DeriveKey produced an empty string value")
	}
}

// TestDeriveKeyDistinctOwnersSameHandle proves two callers passing the same handle
// get DIFFERENT keys, so a handle is namespaced by the host-derived identity.
func TestDeriveKeyDistinctOwnersSameHandle(t *testing.T) {
	t.Parallel()
	a := registry.DeriveKey(state.Identity{Tenant: "t1", Caller: "c1"}, "same-handle")
	b := registry.DeriveKey(state.Identity{Tenant: "t2", Caller: "c2"}, "same-handle")
	if a == b {
		t.Fatalf("distinct owners with the same handle collided: %q", a.String())
	}
}

// TestPropertyNoHintEscapesNamespace is the namespace-escape-proof property: no
// crafted handle for caller A can produce the same Key as ANY (owner B, handle B)
// when (A, handleA) != (B, handleB). The length-prefixed pre-image means a handle
// can never forge another caller's identity field via an embedded delimiter, so
// two distinct triples never share a key. This is the structural guarantee that a
// body-supplied hint can never land in another caller's namespace.
func TestPropertyNoHintEscapesNamespace(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		// Two independent (tenant, caller, handle) triples, drawn from a small
		// alphabet that includes the kind of delimiter bytes a delimiter-based
		// scheme would be vulnerable to.
		alpha := rapid.StringMatching(`[a-z:|/\x00-]{0,12}`)
		tA := alpha.Draw(rt, "tenantA")
		cA := alpha.Draw(rt, "callerA")
		hA := alpha.Draw(rt, "handleA")
		tB := alpha.Draw(rt, "tenantB")
		cB := alpha.Draw(rt, "callerB")
		hB := alpha.Draw(rt, "handleB")

		keyA := registry.DeriveKey(state.Identity{Tenant: tA, Caller: cA}, hA)
		keyB := registry.DeriveKey(state.Identity{Tenant: tB, Caller: cB}, hB)

		sameTriple := tA == tB && cA == cB && hA == hB
		if sameTriple {
			if keyA != keyB {
				rt.Fatalf("identical triple produced different keys")
			}
			return
		}
		if keyA == keyB {
			rt.Fatalf("distinct triples (%q/%q/%q) vs (%q/%q/%q) collided to key %q",
				tA, cA, hA, tB, cB, hB, keyA.String())
		}
	})
}

// TestCustodianReserveCommitBind exercises the sole-custody wrappers end to end:
// Reserve, BindContainerName after Commit, and the lookup the owner sees.
func TestCustodianReserveCommitBind(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	ctx := context.Background()
	owner := state.Identity{Tenant: "t1", Caller: "c1"}
	key := registry.DeriveKey(owner, "h1")

	if _, err := c.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if _, err := c.Commit(ctx, key, owner); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	row, err := c.BindContainerName(ctx, key, owner, "ocu-container-1")
	if err != nil {
		t.Fatalf("BindContainerName: %v", err)
	}
	if row.ContainerName != "ocu-container-1" {
		t.Fatalf("bound container name = %q, want ocu-container-1", row.ContainerName)
	}
	if row.State != state.StateActive {
		t.Fatalf("row state = %v, want StateActive", row.State)
	}

	got, err := c.LookupForCaller(ctx, key, owner)
	if err != nil {
		t.Fatalf("LookupForCaller (owner): %v", err)
	}
	if got.ContainerName != "ocu-container-1" {
		t.Fatalf("looked-up container name = %q, want ocu-container-1", got.ContainerName)
	}
}

// TestLookupForCallerForeignOwnerIndistinguishable is the cross-tenant
// enumeration block: a foreign owner addressing a real key gets ErrNotOwned, the
// SAME error a never-reserved key returns, so "exists but not yours" cannot be
// told apart from "absent".
func TestLookupForCallerForeignOwnerIndistinguishable(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	ctx := context.Background()
	owner := state.Identity{Tenant: "t1", Caller: "c1"}
	attacker := state.Identity{Tenant: "t2", Caller: "c2"}
	key := registry.DeriveKey(owner, "h1")

	if _, err := c.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	// The attacker addresses the victim's real key under its own identity. Because
	// DeriveKey namespaces by identity, the attacker cannot even derive the
	// victim's key from its own identity — but even handed the victim's exact key,
	// LookupForCaller refuses with ErrNotOwned and discloses nothing.
	_, errExisting := c.LookupForCaller(ctx, key, attacker)
	if !errors.Is(errExisting, registry.ErrNotOwned) {
		t.Fatalf("foreign owner on existing row: error %v, want ErrNotOwned", errExisting)
	}

	// A never-reserved key returns the SAME error, so the two are indistinguishable.
	absent := registry.DeriveKey(attacker, "never-reserved")
	_, errAbsent := c.LookupForCaller(ctx, absent, attacker)
	if !errors.Is(errAbsent, registry.ErrNotOwned) {
		t.Fatalf("absent row: error %v, want ErrNotOwned", errAbsent)
	}

	if errExisting.Error() != errAbsent.Error() {
		t.Fatalf("disclosure leak: existing-foreign %q distinguishable from absent %q",
			errExisting.Error(), errAbsent.Error())
	}
}

// TestReservedAndActiveKeysUnsupported proves the fail-closed branch: the frozen
// in-memory Store does not implement LiveLister, so ReservedAndActiveKeys returns
// ErrEnumerationUnsupported rather than an empty slice — RevokeAll must refuse
// rather than claim it force-killed every row.
func TestReservedAndActiveKeysUnsupported(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	_, err := c.ReservedAndActiveKeys(context.Background())
	if !errors.Is(err, registry.ErrEnumerationUnsupported) {
		t.Fatalf("ReservedAndActiveKeys on non-enumerating Store: error %v, want ErrEnumerationUnsupported", err)
	}
}

// TestReleaseRowReleasesEnumeratedRow proves the reconciler/kill-switch seam:
// ReleaseRow (and its ForceReleaseRow twin) release a row addressed by its own raw
// key and owner — the shape the enumeration path hands back — driving it to the
// RELEASED tombstone, idempotently.
func TestReleaseRowReleasesEnumeratedRow(t *testing.T) {
	t.Parallel()
	c, store := newCustodian(t)
	ctx := context.Background()
	owner := state.Identity{Tenant: "t", Caller: "c"}
	key := registry.DeriveKey(owner, "handle")

	if _, err := c.Reserve(ctx, key, owner); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	row, err := store.LookupSession(ctx, key.String())
	if err != nil {
		t.Fatalf("LookupSession: %v", err)
	}

	released, err := c.ReleaseRow(ctx, row)
	if err != nil {
		t.Fatalf("ReleaseRow: %v", err)
	}
	if released.State != state.StateReleased {
		t.Fatalf("ReleaseRow state = %v, want RELEASED", released.State)
	}
	// Idempotent: ForceReleaseRow on the already-released row returns the tombstone, no
	// error, no double credit.
	again, err := c.ForceReleaseRow(ctx, row)
	if err != nil {
		t.Fatalf("ForceReleaseRow (idempotent): %v", err)
	}
	if again.State != state.StateReleased {
		t.Fatalf("ForceReleaseRow state = %v, want RELEASED", again.State)
	}
}

// listerStore wraps an in-memory Store and adds the LiveLister capability,
// modelling the durable Store a later phase grows. It records every live row the
// test reserved so ReservedAndActiveKeys returns the RESERVED+ACTIVE set.
type listerStore struct {
	state.Store
	live []state.SessionRow
}

func (s *listerStore) LiveSessions(ctx context.Context) ([]state.SessionRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]state.SessionRow, len(s.live))
	copy(out, s.live)
	return out, nil
}

// TestReservedAndActiveKeysWithLister proves the capability seam lights up the
// moment a Store implements LiveLister: the Custodian returns the live rows.
func TestReservedAndActiveKeysWithLister(t *testing.T) {
	t.Parallel()
	inner := state.NewInMemory(state.NewFakeClock(regStart))
	store := &listerStore{
		Store: inner,
		live: []state.SessionRow{
			{Key: "k-reserved", State: state.StateReserved},
			{Key: "k-active", State: state.StateActive},
		},
	}
	c := registry.NewCustodian(store)

	rows, err := c.ReservedAndActiveKeys(context.Background())
	if err != nil {
		t.Fatalf("ReservedAndActiveKeys with LiveLister: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ReservedAndActiveKeys returned %d rows, want 2 (RESERVED+ACTIVE)", len(rows))
	}
	// RESERVED rows must be included (a just-reserved-not-committed session).
	var sawReserved bool
	for _, r := range rows {
		if r.State == state.StateReserved {
			sawReserved = true
		}
	}
	if !sawReserved {
		t.Fatalf("ReservedAndActiveKeys dropped the RESERVED row")
	}
}
