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

// TestDeriveKeyGolden pins the EXACT digest DeriveKey produces for a fixed
// (Tenant, Caller, handle) triple. The distinctness properties above prove keys
// differ from each other, but they pass even if the length-prefixed pre-image is
// serialized wrongly (a different prefix width, a dropped field, an un-written
// length) — every key just shifts together and stays mutually distinct. This
// golden anchor is the byte-exact witness: the digest is computed independently
// (sha256 over keyVersion ++ each of Tenant/Caller/handle as an 8-byte big-endian
// length followed by its bytes), so ANY change to the serialization — the prefix
// width, the field set, or the length computation — moves the digest and reds
// this test. It is what makes the pre-image construction (not just its
// distinctness) load-bearing and mutation-covered.
func TestDeriveKeyGolden(t *testing.T) {
	t.Parallel()
	got := registry.DeriveKey(state.Identity{Tenant: "t-gold", Caller: "c-gold"}, "h-gold").String()
	const want = "e191b4aeec02b7b0456067f25e9c945e27ebcdd00b8e4ab28f0d9d2103fbc639"
	if got != want {
		t.Fatalf("DeriveKey golden digest drift:\n got %q\nwant %q\n"+
			"(the length-prefixed pre-image serialization changed — prefix width, field set, or length computation)", got, want)
	}
}

// TestDeriveKeyEveryFieldIsLoadBearing proves each of the three identity inputs
// independently changes the key: flipping ONLY the Tenant, ONLY the Caller, or
// ONLY the handle (holding the other two fixed) must move the digest. A
// serialization that drops or fails to write any one field would leave that
// field's mutation undetected — these three assertions kill exactly that mutant
// class (a writeField call whose effect is nulled).
func TestDeriveKeyEveryFieldIsLoadBearing(t *testing.T) {
	t.Parallel()
	base := registry.DeriveKey(state.Identity{Tenant: "t", Caller: "c"}, "h")
	tenantFlip := registry.DeriveKey(state.Identity{Tenant: "T", Caller: "c"}, "h")
	callerFlip := registry.DeriveKey(state.Identity{Tenant: "t", Caller: "C"}, "h")
	handleFlip := registry.DeriveKey(state.Identity{Tenant: "t", Caller: "c"}, "H")
	if base == tenantFlip {
		t.Errorf("flipping Tenant did not change the key — Tenant is not load-bearing in the pre-image")
	}
	if base == callerFlip {
		t.Errorf("flipping Caller did not change the key — Caller is not load-bearing in the pre-image")
	}
	if base == handleFlip {
		t.Errorf("flipping handle did not change the key — handle is not load-bearing in the pre-image")
	}
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

// nonListerStore wraps a state.Store but does NOT promote LiveSessions: it embeds
// the state.Store INTERFACE, whose method set carries no LiveSessions, so the
// concrete *nonListerStore does not satisfy registry.LiveLister even though the
// underlying value (the in-memory store) now does. It models a hypothetical Store
// leg that has not opted into live enumeration, so the fail-closed branch stays
// covered after both shipped legs grew the capability.
type nonListerStore struct {
	state.Store
}

// TestReservedAndActiveKeysUnsupported proves the fail-closed branch is intact for
// a Store that does NOT implement LiveLister: ReservedAndActiveKeys returns
// ErrEnumerationUnsupported rather than an empty slice, so RevokeAll refuses rather
// than claiming it force-killed every row. Both SHIPPED legs (in-memory, Postgres)
// now implement LiveSessions — that is proven by the store conformance suite — so
// this case wraps the in-memory store in a non-promoting shim to keep the
// fail-closed branch under test.
func TestReservedAndActiveKeysUnsupported(t *testing.T) {
	t.Parallel()
	inner := state.NewInMemory(state.NewFakeClock(regStart))
	c := registry.NewCustodian(&nonListerStore{Store: inner})
	_, err := c.ReservedAndActiveKeys(context.Background())
	if !errors.Is(err, registry.ErrEnumerationUnsupported) {
		t.Fatalf("ReservedAndActiveKeys on non-enumerating Store: error %v, want ErrEnumerationUnsupported", err)
	}
}

// TestReservedAndActiveKeysShippedInMemory proves the in-memory leg's LiveSessions
// lights up ReservedAndActiveKeys with no change above the Custodian: a custodian
// over the real shipped in-memory store enumerates the live RESERVED+ACTIVE rows
// (not the ErrEnumerationUnsupported path the no-lister shim still exercises). This
// is the boot-reconcile unblock — the daemon no longer dies on a healthy host.
func TestReservedAndActiveKeysShippedInMemory(t *testing.T) {
	t.Parallel()
	c, store := newCustodian(t)
	ctx := context.Background()
	owner := state.Identity{Tenant: "t", Caller: "c"}

	reserved := registry.DeriveKey(owner, "handle-reserved")
	active := registry.DeriveKey(owner, "handle-active")
	released := registry.DeriveKey(owner, "handle-released")
	if _, err := c.Reserve(ctx, reserved, owner); err != nil {
		t.Fatalf("Reserve reserved: %v", err)
	}
	if _, err := c.Reserve(ctx, active, owner); err != nil {
		t.Fatalf("Reserve active: %v", err)
	}
	if _, err := c.Commit(ctx, active, owner); err != nil {
		t.Fatalf("Commit active: %v", err)
	}
	if _, err := c.Reserve(ctx, released, owner); err != nil {
		t.Fatalf("Reserve released: %v", err)
	}
	if _, err := c.Release(ctx, released, owner); err != nil {
		t.Fatalf("Release released: %v", err)
	}
	_ = store

	rows, err := c.ReservedAndActiveKeys(ctx)
	if err != nil {
		t.Fatalf("ReservedAndActiveKeys on the shipped in-memory store: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ReservedAndActiveKeys: want 2 live rows (RESERVED+ACTIVE), got %d (%+v)", len(rows), rows)
	}
	for _, r := range rows {
		if r.State == state.StateReleased {
			t.Fatalf("ReservedAndActiveKeys must exclude the RELEASED tombstone, got %+v", rows)
		}
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

// TestLookupForCallerTransientErrorPropagates proves a TRANSIENT store failure is
// NOT collapsed into the not-addressable refusal. LookupForCaller maps only
// state.ErrReservationNotFound to ErrNotOwned (so absent and foreign-owned are
// indistinguishable); any OTHER store error — here ErrStoreUnavailable, surfaced
// by a cancelled context — must propagate UNCHANGED so a transient backing-store
// fault is never silently reported as "not yours". Without this, the
// not-found-branch guard could be widened to swallow every error and the suite
// would not notice.
func TestLookupForCallerTransientErrorPropagates(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	owner := state.Identity{Tenant: "t1", Caller: "c1"}
	key := registry.DeriveKey(owner, "h-transient")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a cancelled context makes the in-memory store fail closed with ErrStoreUnavailable

	_, err := c.LookupForCaller(ctx, key, owner)
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("transient store error: want ErrStoreUnavailable propagated, got %v", err)
	}
	if errors.Is(err, registry.ErrNotOwned) {
		t.Fatalf("a transient store error was collapsed into ErrNotOwned — a backing-store fault must not read as not-addressable")
	}
}

// TestReservedAndActiveKeysTransientErrorPropagates proves the enumeration does
// not swallow a transient lister failure into an empty result. A cancelled
// context makes the in-memory LiveSessions fail closed with ErrStoreUnavailable;
// ReservedAndActiveKeys must propagate it (not return nil, nil), because
// RevokeAll's force-kill-every step treats an empty slice as "no live rows" and a
// swallowed error would leave a just-reserved session alive.
func TestReservedAndActiveKeysTransientErrorPropagates(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rows, err := c.ReservedAndActiveKeys(ctx)
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("transient enumeration error: want ErrStoreUnavailable propagated, got %v", err)
	}
	if rows != nil {
		t.Fatalf("a transient enumeration error returned %d rows; want nil (no silent empty set)", len(rows))
	}
}

// TestEnrichedLiveSessionsTransientErrorPropagates is the same fail-closed
// propagation for the admin read-API enumeration: a cancelled context makes the
// enriched lister fail with ErrStoreUnavailable, which EnrichedLiveSessions must
// propagate rather than swallow into an empty set (the read surface must surface
// the fault, never render an empty dashboard as if no sessions were live).
func TestEnrichedLiveSessionsTransientErrorPropagates(t *testing.T) {
	t.Parallel()
	c, _ := newCustodian(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rows, err := c.EnrichedLiveSessions(ctx)
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("transient enriched-enumeration error: want ErrStoreUnavailable propagated, got %v", err)
	}
	if rows != nil {
		t.Fatalf("a transient enriched-enumeration error returned %d rows; want nil", len(rows))
	}
}
