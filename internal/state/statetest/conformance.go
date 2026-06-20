// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package statetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// conformanceStart is the fixed instant the suite anchors its FakeClock on, so
// every leg runs against a reproducible, deterministic time source.
var conformanceStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// RunConformance is the single shared functional conformance suite every Store
// leg must pass. The in-memory leg runs it on the minimal shelf; the Postgres
// leg runs the identical suite for cross-restart durability, so both legs are
// held to one behavioural contract rather than two drifting test sets.
//
// newStore builds a fresh, empty Store backed by the supplied Clock. Each
// subtest constructs its own store so cases never share state. The Clock the
// suite injects is the deterministic FakeClock, since no functional case here
// depends on wall-clock motion (the Clock's setback invariant is proven in the
// clock tests); the suite only requires that the Store stamps time through the
// injected seam rather than calling the OS clock.
//
// The cases below are organised by the requirement they pin, in the same
// fail-closed order the Store interface documents: reservation lifecycle, the
// no-orphan refusal paths, authority, the deny posture (kill-switch then
// denylist), the write-once container_name bind, and the atomic quota counter.
func RunConformance(t *testing.T, newStore func(state.Clock) state.Store) {
	t.Helper()

	// owner and other are two distinct host-derived identities. Authority cases
	// mutate a row owned by owner with other to prove the foreign caller is
	// refused on identity, not on state.
	owner := state.Identity{Tenant: "tenant-a", Caller: "caller-1"}
	other := state.Identity{Tenant: "tenant-b", Caller: "caller-2"}

	// newFixture returns a fresh store backed by a fresh FakeClock anchored at a
	// fixed instant, so every subtest is hermetic and reproducible. The suite
	// injects the deterministic clock through the constructor; no functional case
	// here drives wall-clock motion, so the clock handle itself is not surfaced.
	newFixture := func() state.Store {
		return newStore(state.NewFakeClock(conformanceStart))
	}

	ctx := context.Background()

	t.Run("Reserve writes a RESERVED row visible to Lookup", func(t *testing.T) {
		s := newFixture()
		row, err := s.Reserve(ctx, "k1", owner)
		if err != nil {
			t.Fatalf("Reserve: unexpected error %v", err)
		}
		if row.Key != "k1" || row.Owner != owner || row.State != state.StateReserved {
			t.Fatalf("Reserve row: want key=k1 owner=%v RESERVED, got %+v", owner, row)
		}
		if row.ContainerName != "" {
			t.Fatalf("Reserve row: container_name must be empty, got %q", row.ContainerName)
		}
		got, err := s.LookupSession(ctx, "k1")
		if err != nil {
			t.Fatalf("LookupSession after Reserve: unexpected error %v", err)
		}
		if got != row {
			t.Fatalf("LookupSession mismatch: reserved %+v, looked up %+v", row, got)
		}
	})

	t.Run("Commit promotes RESERVED to ACTIVE", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		row, err := s.Commit(ctx, "k1", owner)
		if err != nil {
			t.Fatalf("Commit: unexpected error %v", err)
		}
		if row.State != state.StateActive {
			t.Fatalf("Commit: want ACTIVE, got state %v", row.State)
		}
		got := mustLookup(ctx, t, s, "k1")
		if got.State != state.StateActive {
			t.Fatalf("LookupSession after Commit: want ACTIVE, got %v", got.State)
		}
	})

	t.Run("Release moves a row to the RELEASED tombstone", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustCommit(ctx, t, s, "k1", owner)
		row, err := s.Release(ctx, "k1", owner)
		if err != nil {
			t.Fatalf("Release: unexpected error %v", err)
		}
		if row.State != state.StateReleased {
			t.Fatalf("Release: want RELEASED, got state %v", row.State)
		}
		// The tombstone stays visible (not deleted): Lookup still returns it.
		got, err := s.LookupSession(ctx, "k1")
		if err != nil {
			t.Fatalf("LookupSession after Release: tombstone must stay visible, got error %v", err)
		}
		if got.State != state.StateReleased {
			t.Fatalf("LookupSession after Release: want RELEASED tombstone, got %v", got.State)
		}
	})

	t.Run("Reserve can re-reserve a RELEASED key (tombstone is not live)", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustRelease(ctx, t, s, "k1", owner)
		// A released tombstone is not a live double-book; a fresh reserve succeeds.
		row, err := s.Reserve(ctx, "k1", owner)
		if err != nil {
			t.Fatalf("Reserve over a RELEASED key: unexpected error %v", err)
		}
		if row.State != state.StateReserved {
			t.Fatalf("Reserve over a RELEASED key: want RESERVED, got %v", row.State)
		}
	})

	t.Run("double Reserve of a live key returns ErrReservationExists and leaves the first untouched", func(t *testing.T) {
		s := newFixture()
		first := mustReserve(ctx, t, s, "k1", owner)
		// A second reserve, even by a different owner, must not overwrite the row.
		_, err := s.Reserve(ctx, "k1", other)
		if !errors.Is(err, state.ErrReservationExists) {
			t.Fatalf("double Reserve: want ErrReservationExists, got %v", err)
		}
		got := mustLookup(ctx, t, s, "k1")
		if got != first {
			t.Fatalf("double Reserve must leave the first row untouched: was %+v, now %+v", first, got)
		}
	})

	t.Run("Commit and Release of an unknown key return ErrReservationNotFound", func(t *testing.T) {
		s := newFixture()
		if _, err := s.Commit(ctx, "missing", owner); !errors.Is(err, state.ErrReservationNotFound) {
			t.Fatalf("Commit unknown: want ErrReservationNotFound, got %v", err)
		}
		if _, err := s.Release(ctx, "missing", owner); !errors.Is(err, state.ErrReservationNotFound) {
			t.Fatalf("Release unknown: want ErrReservationNotFound, got %v", err)
		}
		if _, err := s.BindContainerName(ctx, "missing", owner, "ctr-x"); !errors.Is(err, state.ErrReservationNotFound) {
			t.Fatalf("BindContainerName unknown: want ErrReservationNotFound, got %v", err)
		}
		if _, err := s.LookupSession(ctx, "missing"); !errors.Is(err, state.ErrReservationNotFound) {
			t.Fatalf("LookupSession unknown: want ErrReservationNotFound, got %v", err)
		}
	})

	t.Run("Commit a RELEASED row returns ErrReservationConflict", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustRelease(ctx, t, s, "k1", owner)
		// RELEASED is terminal; no path forward to ACTIVE.
		if _, err := s.Commit(ctx, "k1", owner); !errors.Is(err, state.ErrReservationConflict) {
			t.Fatalf("Commit a RELEASED row: want ErrReservationConflict, got %v", err)
		}
	})

	t.Run("Commit an ACTIVE row returns ErrReservationConflict", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustCommit(ctx, t, s, "k1", owner)
		// No double-commit: RESERVED is the only state Commit accepts.
		if _, err := s.Commit(ctx, "k1", owner); !errors.Is(err, state.ErrReservationConflict) {
			t.Fatalf("double Commit: want ErrReservationConflict, got %v", err)
		}
	})

	t.Run("a foreign Identity mutator is refused with ErrReservationConflict (authority)", func(t *testing.T) {
		s := newFixture()
		original := mustReserve(ctx, t, s, "k1", owner)

		// Commit, Release, and BindContainerName all key authority on the
		// host-derived Owner; the foreign caller is refused on identity.
		if _, err := s.Commit(ctx, "k1", other); !errors.Is(err, state.ErrReservationConflict) {
			t.Fatalf("foreign Commit: want ErrReservationConflict, got %v", err)
		}
		if _, err := s.Release(ctx, "k1", other); !errors.Is(err, state.ErrReservationConflict) {
			t.Fatalf("foreign Release: want ErrReservationConflict, got %v", err)
		}
		if _, err := s.BindContainerName(ctx, "k1", other, "ctr-x"); !errors.Is(err, state.ErrReservationConflict) {
			t.Fatalf("foreign BindContainerName: want ErrReservationConflict, got %v", err)
		}

		// The foreign attempts must not have touched the row.
		got := mustLookup(ctx, t, s, "k1")
		if got != original {
			t.Fatalf("foreign mutators must not touch the row: was %+v, now %+v", original, got)
		}
	})

	t.Run("Release is idempotent: twice yields the terminal row, nil, no double credit", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		first := mustRelease(ctx, t, s, "k1", owner)
		// A second Release of the same terminal row is a no-op: nil error, the
		// same terminal row, and no second capacity credit.
		second, err := s.Release(ctx, "k1", owner)
		if err != nil {
			t.Fatalf("idempotent Release: want nil error, got %v", err)
		}
		if second.State != state.StateReleased {
			t.Fatalf("idempotent Release: want RELEASED, got %v", second.State)
		}
		if second != first {
			t.Fatalf("idempotent Release must return the same terminal row: first %+v, second %+v", first, second)
		}
	})

	t.Run("kill-switch: SetDeny(ScopeGlobal) makes Reserve return ErrKillSwitchEngaged with no orphan row", func(t *testing.T) {
		s := newFixture()
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal, Reason: "drill"}); err != nil {
			t.Fatalf("SetDeny global: unexpected error %v", err)
		}
		if _, err := s.Reserve(ctx, "k1", owner); !errors.Is(err, state.ErrKillSwitchEngaged) {
			t.Fatalf("Reserve under kill-switch: want ErrKillSwitchEngaged, got %v", err)
		}
		// No-orphan: a refused create writes no row, so Lookup finds nothing.
		if _, err := s.LookupSession(ctx, "k1"); !errors.Is(err, state.ErrReservationNotFound) {
			t.Fatalf("kill-switch refusal must leave no row: want ErrReservationNotFound, got %v", err)
		}
	})

	t.Run("ClearDeny lifts the kill-switch", func(t *testing.T) {
		s := newFixture()
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal}); err != nil {
			t.Fatalf("SetDeny global: unexpected error %v", err)
		}
		if err := s.ClearDeny(ctx, state.ScopeGlobal, ""); err != nil {
			t.Fatalf("ClearDeny global: unexpected error %v", err)
		}
		// With the switch lifted, the same create now succeeds.
		if _, err := s.Reserve(ctx, "k1", owner); err != nil {
			t.Fatalf("Reserve after ClearDeny: unexpected error %v", err)
		}
	})

	t.Run("denylist: SetDeny(ScopeSession,key) refuses only that key, a sibling still reserves", func(t *testing.T) {
		s := newFixture()
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "denied", Reason: "abuse"}); err != nil {
			t.Fatalf("SetDeny session: unexpected error %v", err)
		}
		// The denylisted key is refused with no orphan.
		if _, err := s.Reserve(ctx, "denied", owner); !errors.Is(err, state.ErrSessionDenied) {
			t.Fatalf("Reserve denied key: want ErrSessionDenied, got %v", err)
		}
		if _, err := s.LookupSession(ctx, "denied"); !errors.Is(err, state.ErrReservationNotFound) {
			t.Fatalf("denylist refusal must leave no row: want ErrReservationNotFound, got %v", err)
		}
		// A sibling key, not on the denylist, reserves normally.
		if _, err := s.Reserve(ctx, "allowed", owner); err != nil {
			t.Fatalf("Reserve sibling key: unexpected error %v", err)
		}
	})

	t.Run("LoadDeny returns exactly the written set, scope-tagged", func(t *testing.T) {
		s := newFixture()
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal, Reason: "global"}); err != nil {
			t.Fatalf("SetDeny global: unexpected error %v", err)
		}
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "s1", Reason: "one"}); err != nil {
			t.Fatalf("SetDeny s1: unexpected error %v", err)
		}
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "s2", Reason: "two"}); err != nil {
			t.Fatalf("SetDeny s2: unexpected error %v", err)
		}

		entries, err := s.LoadDeny(ctx)
		if err != nil {
			t.Fatalf("LoadDeny: unexpected error %v", err)
		}
		got := indexDeny(entries)
		if len(got) != 3 {
			t.Fatalf("LoadDeny: want 3 entries, got %d (%+v)", len(got), entries)
		}
		if _, ok := got[denyMapKey(state.ScopeGlobal, "")]; !ok {
			t.Fatalf("LoadDeny: missing the global kill-switch entry: %+v", entries)
		}
		if e, ok := got[denyMapKey(state.ScopeSession, "s1")]; !ok || e.Reason != "one" {
			t.Fatalf("LoadDeny: missing or wrong s1 entry: %+v", entries)
		}
		if e, ok := got[denyMapKey(state.ScopeSession, "s2")]; !ok || e.Reason != "two" {
			t.Fatalf("LoadDeny: missing or wrong s2 entry: %+v", entries)
		}
	})

	t.Run("ClearDeny removes one entry without disturbing the other", func(t *testing.T) {
		s := newFixture()
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "s1"}); err != nil {
			t.Fatalf("SetDeny s1: unexpected error %v", err)
		}
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "s2"}); err != nil {
			t.Fatalf("SetDeny s2: unexpected error %v", err)
		}
		if err := s.ClearDeny(ctx, state.ScopeSession, "s1"); err != nil {
			t.Fatalf("ClearDeny s1: unexpected error %v", err)
		}
		// s1 is lifted and reserves; s2 is still denied.
		if _, err := s.Reserve(ctx, "s1", owner); err != nil {
			t.Fatalf("Reserve s1 after ClearDeny: unexpected error %v", err)
		}
		if _, err := s.Reserve(ctx, "s2", owner); !errors.Is(err, state.ErrSessionDenied) {
			t.Fatalf("Reserve s2: still denied, want ErrSessionDenied, got %v", err)
		}
	})

	t.Run("kill-switch precedence: global is reported even when the key is also denylisted", func(t *testing.T) {
		s := newFixture()
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeGlobal}); err != nil {
			t.Fatalf("SetDeny global: unexpected error %v", err)
		}
		if err := s.SetDeny(ctx, state.DenyEntry{Scope: state.ScopeSession, Key: "k1"}); err != nil {
			t.Fatalf("SetDeny session: unexpected error %v", err)
		}
		// Fail-closed order: the global kill-switch wins the report.
		if _, err := s.Reserve(ctx, "k1", owner); !errors.Is(err, state.ErrKillSwitchEngaged) {
			t.Fatalf("Reserve with both denies: want ErrKillSwitchEngaged first, got %v", err)
		}
	})

	t.Run("BindContainerName is write-once on the same row (rebind returns ErrBindingExists)", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustCommit(ctx, t, s, "k1", owner)
		row, err := s.BindContainerName(ctx, "k1", owner, "ctr-1")
		if err != nil {
			t.Fatalf("first BindContainerName: unexpected error %v", err)
		}
		if row.ContainerName != "ctr-1" {
			t.Fatalf("BindContainerName: want container_name ctr-1, got %q", row.ContainerName)
		}
		// A rebind, even to the same name, is refused: the bind is write-once.
		if _, err := s.BindContainerName(ctx, "k1", owner, "ctr-2"); !errors.Is(err, state.ErrBindingExists) {
			t.Fatalf("rebind: want ErrBindingExists, got %v", err)
		}
		// The original binding stands.
		got := mustLookup(ctx, t, s, "k1")
		if got.ContainerName != "ctr-1" {
			t.Fatalf("rebind must not change the binding: want ctr-1, got %q", got.ContainerName)
		}
	})

	t.Run("BindContainerName rejects a container_name already bound to another row", func(t *testing.T) {
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustCommit(ctx, t, s, "k1", owner)
		if _, err := s.BindContainerName(ctx, "k1", owner, "shared"); err != nil {
			t.Fatalf("bind k1: unexpected error %v", err)
		}
		mustReserve(ctx, t, s, "k2", owner)
		mustCommit(ctx, t, s, "k2", owner)
		// Two sessions can never claim one runtime identity.
		if _, err := s.BindContainerName(ctx, "k2", owner, "shared"); !errors.Is(err, state.ErrBindingExists) {
			t.Fatalf("duplicate container_name on another row: want ErrBindingExists, got %v", err)
		}
		// k2 must remain unbound.
		got := mustLookup(ctx, t, s, "k2")
		if got.ContainerName != "" {
			t.Fatalf("refused duplicate bind must leave k2 unbound, got %q", got.ContainerName)
		}
	})

	t.Run("releasing a bound row frees its container_name for a later session", func(t *testing.T) {
		// A container_name is unique only across LIVE sessions. Once the session
		// that held it is released, a different session must be able to claim the
		// same runtime identity — otherwise the reverse index leaks and the name
		// is permanently unbindable. This regression-guards the in-memory leg's
		// boundNames index and the Postgres leg's NULL-on-re-reserve path against
		// drifting apart under one shared contract.
		s := newFixture()
		mustReserve(ctx, t, s, "k1", owner)
		mustCommit(ctx, t, s, "k1", owner)
		if _, err := s.BindContainerName(ctx, "k1", owner, "ctr-recycle"); err != nil {
			t.Fatalf("bind k1: unexpected error %v", err)
		}
		mustRelease(ctx, t, s, "k1", owner)

		// Re-reserving k1 must clear the freed name from the index (the tombstone
		// is overwritten with an unbound row).
		mustReserve(ctx, t, s, "k1", owner)
		if got := mustLookup(ctx, t, s, "k1"); got.ContainerName != "" {
			t.Fatalf("re-reserved k1 must be unbound, got %q", got.ContainerName)
		}

		// A different session must now be able to claim the released name.
		mustReserve(ctx, t, s, "k2", owner)
		mustCommit(ctx, t, s, "k2", owner)
		if _, err := s.BindContainerName(ctx, "k2", owner, "ctr-recycle"); err != nil {
			t.Fatalf("k2 must reuse the freed container_name, got %v", err)
		}
	})

	t.Run("Charge below the limit returns the running value", func(t *testing.T) {
		s := newFixture()
		key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
		v, err := s.Charge(ctx, key, 1, 5)
		if err != nil {
			t.Fatalf("Charge +1: unexpected error %v", err)
		}
		if v != 1 {
			t.Fatalf("Charge +1: want running value 1, got %d", v)
		}
		v, err = s.Charge(ctx, key, 2, 5)
		if err != nil {
			t.Fatalf("Charge +2: unexpected error %v", err)
		}
		if v != 3 {
			t.Fatalf("Charge +2: want running value 3, got %d", v)
		}
	})

	t.Run("Charge that would exceed the limit returns ErrQuotaExceeded and leaves the cell unchanged", func(t *testing.T) {
		s := newFixture()
		key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
		if _, err := s.Charge(ctx, key, 4, 5); err != nil {
			t.Fatalf("Charge +4: unexpected error %v", err)
		}
		// 4 + 2 > 5: refused, cell stays at 4.
		if _, err := s.Charge(ctx, key, 2, 5); !errors.Is(err, state.ErrQuotaExceeded) {
			t.Fatalf("Charge over limit: want ErrQuotaExceeded, got %v", err)
		}
		got, err := s.ReadQuota(ctx, key)
		if err != nil {
			t.Fatalf("ReadQuota: unexpected error %v", err)
		}
		if got != 4 {
			t.Fatalf("refused Charge must leave the cell unchanged: want 4, got %d", got)
		}
	})

	t.Run("a fresh-cell delta greater than the limit is refused (the first charge is guarded)", func(t *testing.T) {
		s := newFixture()
		key := state.QuotaKey{Dim: state.DimStorageGB, Identity: owner}
		// The cell is absent; the first-ever charge is guarded against the limit
		// exactly as the conflict path is.
		if _, err := s.Charge(ctx, key, 10, 5); !errors.Is(err, state.ErrQuotaExceeded) {
			t.Fatalf("fresh-cell over-limit Charge: want ErrQuotaExceeded, got %v", err)
		}
		got, err := s.ReadQuota(ctx, key)
		if err != nil {
			t.Fatalf("ReadQuota: unexpected error %v", err)
		}
		if got != 0 {
			t.Fatalf("refused fresh-cell Charge must leave the cell at zero, got %d", got)
		}
	})

	t.Run("Charge equal to the limit is allowed (boundary)", func(t *testing.T) {
		s := newFixture()
		key := state.QuotaKey{Dim: state.DimStorageGB, Identity: owner}
		v, err := s.Charge(ctx, key, 5, 5)
		if err != nil {
			t.Fatalf("Charge to exactly the limit: unexpected error %v", err)
		}
		if v != 5 {
			t.Fatalf("Charge to exactly the limit: want 5, got %d", v)
		}
	})

	t.Run("a negative delta releases capacity, is never refused, and saturates at zero", func(t *testing.T) {
		s := newFixture()
		key := state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}
		if _, err := s.Charge(ctx, key, 3, 5); err != nil {
			t.Fatalf("Charge +3: unexpected error %v", err)
		}
		// A release back down: never refused.
		v, err := s.Charge(ctx, key, -2, 5)
		if err != nil {
			t.Fatalf("Charge -2: unexpected error %v", err)
		}
		if v != 1 {
			t.Fatalf("Charge -2: want 1, got %d", v)
		}
		// Over-release saturates at zero; the counter never goes negative, and a
		// negative delta is never refused regardless of the limit.
		v, err = s.Charge(ctx, key, -10, 5)
		if err != nil {
			t.Fatalf("over-release Charge: want no error, got %v", err)
		}
		if v != 0 {
			t.Fatalf("over-release must saturate at zero, got %d", v)
		}
	})

	t.Run("the dimension and the identity partition the counter cell", func(t *testing.T) {
		s := newFixture()
		// Every leg keys the counter cell on the whole QuotaKey (dimension,
		// identity, window). Two charges share a cell only when the whole key
		// matches; a charge under one identity is never visible under a different
		// identity, and two dimensions for one identity are independent cells. The
		// admission gate above constructs the QuotaKey so the billed facet
		// (Caller for the create-rate, Tenant for the rest) is what varies; the
		// Store accumulates per whatever key it is handed.
		a := state.Identity{Tenant: "tenant-x", Caller: "caller-A"}
		b := state.Identity{Tenant: "tenant-y", Caller: "caller-B"}

		// Same key, two charges: they accumulate.
		if _, err := s.Charge(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: a}, 2, 10); err != nil {
			t.Fatalf("Charge A #1: unexpected error %v", err)
		}
		aVal, err := s.Charge(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: a}, 1, 10)
		if err != nil {
			t.Fatalf("Charge A #2: unexpected error %v", err)
		}
		if aVal != 3 {
			t.Fatalf("charges to one cell accumulate: want 3, got %d", aVal)
		}

		// A different identity is a different cell: A's charge is invisible to B.
		bVal, err := s.ReadQuota(ctx, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: b})
		if err != nil {
			t.Fatalf("ReadQuota B: unexpected error %v", err)
		}
		if bVal != 0 {
			t.Fatalf("a charge under A must not be visible under B: got %d", bVal)
		}

		// A different dimension for the same identity is a different cell.
		dimVal, err := s.ReadQuota(ctx, state.QuotaKey{Dim: state.DimStorageGB, Identity: a})
		if err != nil {
			t.Fatalf("ReadQuota A/StorageGB: unexpected error %v", err)
		}
		if dimVal != 0 {
			t.Fatalf("a charge to DimConcurrentSessions must not bleed into DimStorageGB: got %d", dimVal)
		}
	})

	t.Run("a new Window label is a fresh counter (window rollover)", func(t *testing.T) {
		s := newFixture()
		idA := state.Identity{Tenant: "t", Caller: "c"}
		w1 := state.QuotaKey{Dim: state.DimMCPCallsPerMin, Identity: idA, Window: "minute-1"}
		w2 := state.QuotaKey{Dim: state.DimMCPCallsPerMin, Identity: idA, Window: "minute-2"}

		if _, err := s.Charge(ctx, w1, 4, 5); err != nil {
			t.Fatalf("Charge window-1: unexpected error %v", err)
		}
		// The next window is a distinct cell: it starts fresh at zero, so a full
		// charge succeeds without the prior window's count.
		v, err := s.Charge(ctx, w2, 5, 5)
		if err != nil {
			t.Fatalf("Charge window-2: a rolled-over window starts fresh, got error %v", err)
		}
		if v != 5 {
			t.Fatalf("Charge window-2: want fresh count 5, got %d", v)
		}
		// The prior window is undisturbed.
		w1val, err := s.ReadQuota(ctx, w1)
		if err != nil {
			t.Fatalf("ReadQuota window-1: unexpected error %v", err)
		}
		if w1val != 4 {
			t.Fatalf("the prior window must be undisturbed: want 4, got %d", w1val)
		}
	})

	t.Run("ReadQuota of an absent cell is zero and does not create it", func(t *testing.T) {
		s := newFixture()
		key := state.QuotaKey{Dim: state.DimEgressBytesPerDay, Identity: owner, Window: "day-1"}
		v, err := s.ReadQuota(ctx, key)
		if err != nil {
			t.Fatalf("ReadQuota absent: unexpected error %v", err)
		}
		if v != 0 {
			t.Fatalf("ReadQuota of an absent cell: want 0, got %d", v)
		}
	})

	t.Run("LiveSessions returns exactly the RESERVED and ACTIVE rows, never RELEASED", func(t *testing.T) {
		// LiveSessions is the optional live-enumeration capability the boot reconciler
		// and the kill-switch force-kill-every step drive (registry.LiveLister). It is
		// asserted here against the same state.Store both legs build, so the in-memory
		// leg and the Postgres leg are held to one snapshot contract: the live set is
		// exactly the RESERVED+ACTIVE rows, and a RELEASED tombstone is excluded so a
		// reconciler never tries to reclaim capacity already returned.
		s := newFixture()
		lister, ok := s.(liveLister)
		if !ok {
			t.Fatalf("Store %T does not implement LiveSessions: the boot reconciler cannot enumerate live rows, so a healthy host dies at boot", s)
		}

		// k-reserved stays RESERVED; k-active is committed to ACTIVE; k-released is
		// reserved then released to the tombstone. Only the first two are live.
		mustReserve(ctx, t, s, "k-reserved", owner)
		mustReserve(ctx, t, s, "k-active", owner)
		mustCommit(ctx, t, s, "k-active", owner)
		mustReserve(ctx, t, s, "k-released", owner)
		mustRelease(ctx, t, s, "k-released", owner)

		live, err := lister.LiveSessions(ctx)
		if err != nil {
			t.Fatalf("LiveSessions: unexpected error %v", err)
		}

		byKey := make(map[string]state.SessionRow, len(live))
		for _, row := range live {
			if _, dup := byKey[row.Key]; dup {
				t.Fatalf("LiveSessions returned a duplicate row for key %q", row.Key)
			}
			byKey[row.Key] = row
		}
		if len(byKey) != 2 {
			t.Fatalf("LiveSessions: want exactly 2 live rows (RESERVED+ACTIVE), got %d (%+v)", len(byKey), live)
		}
		if r, ok := byKey["k-reserved"]; !ok || r.State != state.StateReserved {
			t.Fatalf("LiveSessions must include the RESERVED row k-reserved, got %+v", live)
		}
		if r, ok := byKey["k-active"]; !ok || r.State != state.StateActive {
			t.Fatalf("LiveSessions must include the ACTIVE row k-active, got %+v", live)
		}
		if _, ok := byKey["k-released"]; ok {
			t.Fatalf("LiveSessions must EXCLUDE the RELEASED tombstone k-released, got %+v", live)
		}
		// The returned rows carry the host-derived owner so the reconciler can release
		// a crashed RESERVED row by its own identity without a re-derivation.
		if got := byKey["k-reserved"]; got.Owner != owner {
			t.Fatalf("LiveSessions row must carry the host-derived owner: want %v, got %v", owner, got.Owner)
		}
	})

	t.Run("LiveSessions on a store with no live rows is the empty set, not an error", func(t *testing.T) {
		// A clean host (no reservations, or only released tombstones) must enumerate
		// to the empty set with a nil error, so the boot reconciler proceeds to bind
		// rather than treating "no orphans" as a failure.
		s := newFixture()
		lister, ok := s.(liveLister)
		if !ok {
			t.Fatalf("Store %T does not implement LiveSessions", s)
		}
		mustReserve(ctx, t, s, "gone", owner)
		mustRelease(ctx, t, s, "gone", owner)

		live, err := lister.LiveSessions(ctx)
		if err != nil {
			t.Fatalf("LiveSessions on a clean host: unexpected error %v", err)
		}
		if len(live) != 0 {
			t.Fatalf("LiveSessions with only a RELEASED tombstone: want the empty set, got %+v", live)
		}
	})

	t.Run("LiveSessions on a cancelled context fails closed with ErrStoreUnavailable", func(t *testing.T) {
		s := newFixture()
		lister, ok := s.(liveLister)
		if !ok {
			t.Fatalf("Store %T does not implement LiveSessions", s)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := lister.LiveSessions(cancelled); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("LiveSessions on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
	})

	t.Run("a cancelled context fails closed with ErrStoreUnavailable", func(t *testing.T) {
		s := newFixture()
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()

		// Every method must treat a torn-down request as a transient store
		// failure, never as an allow.
		if _, err := s.Reserve(cancelled, "k1", owner); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("Reserve on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.LookupSession(cancelled, "k1"); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("LookupSession on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if err := s.SetDeny(cancelled, state.DenyEntry{Scope: state.ScopeGlobal}); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("SetDeny on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.LoadDeny(cancelled); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("LoadDeny on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.Charge(cancelled, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}, 1, 5); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("Charge on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		// The remaining mutators and the quota read must fail closed on the ctx
		// check before any state check, so a torn-down request is a refusal even
		// for an absent row.
		if _, err := s.Commit(cancelled, "k1", owner); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("Commit on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.Release(cancelled, "k1", owner); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("Release on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.BindContainerName(cancelled, "k1", owner, "ctr-x"); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("BindContainerName on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if err := s.ClearDeny(cancelled, state.ScopeGlobal, ""); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("ClearDeny on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
		if _, err := s.ReadQuota(cancelled, state.QuotaKey{Dim: state.DimConcurrentSessions, Identity: owner}); !errors.Is(err, state.ErrStoreUnavailable) {
			t.Fatalf("ReadQuota on cancelled ctx: want ErrStoreUnavailable, got %v", err)
		}
	})
}

// liveLister is the optional live-session enumeration capability the boot
// reconciler and the kill-switch force-kill-every step drive (mirroring
// registry.LiveLister). The conformance suite asserts both Store legs satisfy it
// rather than importing the registry package, so the one behavioural contract —
// the live set is exactly the RESERVED+ACTIVE rows — is held in the shared suite
// where every leg already runs. The signature MUST match the production
// LiveSessions method so a leg that drifts (a wrong return shape) stops satisfying
// the type assertion and the suite fails loudly.
type liveLister interface {
	LiveSessions(ctx context.Context) ([]state.SessionRow, error)
}

// mustReserve reserves key for owner and fails the test on any error.
func mustReserve(ctx context.Context, t *testing.T, s state.Store, key string, owner state.Identity) state.SessionRow {
	t.Helper()
	row, err := s.Reserve(ctx, key, owner)
	if err != nil {
		t.Fatalf("Reserve(%q): unexpected error %v", key, err)
	}
	return row
}

// mustCommit commits key for owner and fails the test on any error.
func mustCommit(ctx context.Context, t *testing.T, s state.Store, key string, owner state.Identity) {
	t.Helper()
	if _, err := s.Commit(ctx, key, owner); err != nil {
		t.Fatalf("Commit(%q): unexpected error %v", key, err)
	}
}

// mustRelease releases key for owner and fails the test on any error.
func mustRelease(ctx context.Context, t *testing.T, s state.Store, key string, owner state.Identity) state.SessionRow {
	t.Helper()
	row, err := s.Release(ctx, key, owner)
	if err != nil {
		t.Fatalf("Release(%q): unexpected error %v", key, err)
	}
	return row
}

// mustLookup looks up key and fails the test on any error.
func mustLookup(ctx context.Context, t *testing.T, s state.Store, key string) state.SessionRow {
	t.Helper()
	row, err := s.LookupSession(ctx, key)
	if err != nil {
		t.Fatalf("LookupSession(%q): unexpected error %v", key, err)
	}
	return row
}

// denyMapKey builds a unique comparison key from a deny entry's scope and key.
// It exists only to index a loaded deny set inside this suite; it is never
// compared against the Store's own internal deny-map key, so its exact byte form
// is irrelevant as long as distinct (scope, key) pairs map to distinct strings.
func denyMapKey(scope state.DenyScope, key string) string {
	return fmt.Sprintf("%d|%s", scope, key)
}

// indexDeny maps a loaded deny set by its scope/key comparison key so a case can
// assert on exact membership without depending on slice order.
func indexDeny(entries []state.DenyEntry) map[string]state.DenyEntry {
	out := make(map[string]state.DenyEntry, len(entries))
	for _, e := range entries {
		out[denyMapKey(e.Scope, e.Key)] = e
	}
	return out
}
