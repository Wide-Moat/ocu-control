// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// conformanceStart is the fixed instant the in-memory property and race tests
// anchor their FakeClock on, so each run drives the Store against a reproducible,
// deterministic time source. No case here depends on wall-clock motion; the
// anchor only pins the injected seam.
var conformanceStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// The property tests below drive the in-memory Store with a sequence of random
// operations and check it lockstep against a tiny in-test model. Each property
// pins one invariant the Store interface promises:
//
//   - P-no-orphan: the count of live (RESERVED+ACTIVE) rows equals successful
//     Reserve minus Release, and a refused Reserve leaves no row.
//   - P-state-machine: only RESERVED→ACTIVE→RELEASED advances; every illegal
//     transition or foreign-owner mutation returns the typed conflict, and the
//     model and the store agree on the resulting state.
//   - P-quota-no-overcommit: an interleaving of charges never carries a cell
//     past its limit and never below zero, and the running arithmetic holds.
//   - P-deny-monotone: a Reserve is refused exactly when the key matches the
//     current deny set, in the documented fail-closed order.

// propOwner is the single host-derived identity the property tests reserve
// under; foreign-owner cases use propOther.
var (
	propOwner = Identity{Tenant: "tenant-p", Caller: "caller-p"}
	propOther = Identity{Tenant: "tenant-q", Caller: "caller-q"}
)

// newPropStore builds a fresh in-memory store on a fixed FakeClock for a
// property run.
func newPropStore() Store {
	return NewInMemory(NewFakeClock(conformanceStart))
}

// TestProperty_NoOrphan drives random Reserve/Release/Commit operations over a
// small key space and checks that the number of live rows the store reports
// always equals the model's live count: every successful Reserve adds one, every
// Release removes one, and a refused Reserve adds nothing (no orphan).
func TestProperty_NoOrphan(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		s := newPropStore()

		keys := []string{"a", "b", "c"}
		// model tracks the state of each key the test believes the store holds;
		// an absent entry means never-reserved (or it would be a tombstone, which
		// we track explicitly as StateReleased).
		model := make(map[string]SessionState)

		isLive := func(st SessionState) bool {
			return st == StateReserved || st == StateActive
		}

		steps := rapid.IntRange(1, 40).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			key := rapid.SampledFrom(keys).Draw(rt, "key")
			op := rapid.SampledFrom([]string{"reserve", "commit", "release"}).Draw(rt, "op")

			switch op {
			case "reserve":
				_, err := s.Reserve(ctx, key, propOwner)
				st, known := model[key]
				switch {
				case known && isLive(st):
					if !errors.Is(err, ErrReservationExists) {
						rt.Fatalf("reserve of a live key %q: want ErrReservationExists, got %v", key, err)
					}
				default:
					// Never-reserved or a tombstone: the reserve must succeed.
					if err != nil {
						rt.Fatalf("reserve of a free key %q: unexpected error %v", key, err)
					}
					model[key] = StateReserved
				}
			case "commit":
				_, err := s.Commit(ctx, key, propOwner)
				st, known := model[key]
				if known && st == StateReserved {
					if err != nil {
						rt.Fatalf("commit of a RESERVED key %q: unexpected error %v", key, err)
					}
					model[key] = StateActive
				} else if !known {
					if !errors.Is(err, ErrReservationNotFound) {
						rt.Fatalf("commit of an unknown key %q: want ErrReservationNotFound, got %v", key, err)
					}
				} else if !errors.Is(err, ErrReservationConflict) {
					rt.Fatalf("commit of a non-RESERVED key %q: want ErrReservationConflict, got %v", key, err)
				}
			case "release":
				_, err := s.Release(ctx, key, propOwner)
				st, known := model[key]
				switch {
				case !known:
					if !errors.Is(err, ErrReservationNotFound) {
						rt.Fatalf("release of an unknown key %q: want ErrReservationNotFound, got %v", key, err)
					}
				default:
					// A live row releases to the tombstone; an already-released row
					// is an idempotent no-op. Either way the result is RELEASED with
					// a nil error.
					if err != nil {
						rt.Fatalf("release of key %q (state %v): unexpected error %v", key, st, err)
					}
					model[key] = StateReleased
				}
			}

			// After every step the store's live-row count must equal the model's.
			wantLive := 0
			for _, st := range model {
				if isLive(st) {
					wantLive++
				}
			}
			gotLive := 0
			for _, k := range keys {
				row, err := s.LookupSession(ctx, k)
				if errors.Is(err, ErrReservationNotFound) {
					continue
				}
				if err != nil {
					rt.Fatalf("lookup %q: unexpected error %v", k, err)
				}
				if isLive(row.State) {
					gotLive++
				}
			}
			if gotLive != wantLive {
				rt.Fatalf("live-row count drift: model=%d store=%d (model=%v)", wantLive, gotLive, model)
			}
		}
	})
}

// TestProperty_StateMachine drives random mutators (including foreign-owner
// attempts) on a single key and checks the store advances only along
// RESERVED→ACTIVE→RELEASED, returns the documented typed error on every illegal
// transition or foreign-owner attempt, and stays lockstep with the model state.
func TestProperty_StateMachine(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		s := newPropStore()

		const key = "k"
		// never marks a key the model believes was never reserved (no row).
		const never = SessionState(255)
		modelState := never
		// modelOwner is the identity that holds the live/tombstoned row, so the
		// model can predict an authority refusal: a mutator by anyone other than
		// the row's owner is an ErrReservationConflict. Reserve assigns it on a
		// successful fresh create.
		var modelOwner Identity

		steps := rapid.IntRange(1, 40).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			op := rapid.SampledFrom([]string{"reserve", "commit", "release", "bind"}).Draw(rt, "op")
			actor := rapid.SampledFrom([]Identity{propOwner, propOther}).Draw(rt, "actor")
			// foreign is true when the actor does not own the existing row; for a
			// fresh reserve there is no owner to mismatch, so Reserve never keys on
			// authority.
			foreign := modelState != never && actor != modelOwner

			switch op {
			case "reserve":
				_, err := s.Reserve(ctx, key, actor)
				// Reserve does not check owner authority (the row does not exist
				// yet for a fresh reserve); the model tracks liveness and, on a
				// successful create, the new owner.
				if modelState == StateReserved || modelState == StateActive {
					if !errors.Is(err, ErrReservationExists) {
						rt.Fatalf("reserve over live: want ErrReservationExists, got %v", err)
					}
				} else {
					if err != nil {
						rt.Fatalf("reserve of free key: unexpected error %v", err)
					}
					modelState = StateReserved
					modelOwner = actor
				}
			case "commit":
				_, err := s.Commit(ctx, key, actor)
				switch {
				case modelState == never:
					if !errors.Is(err, ErrReservationNotFound) {
						rt.Fatalf("commit unknown: want ErrReservationNotFound, got %v", err)
					}
				case foreign:
					if !errors.Is(err, ErrReservationConflict) {
						rt.Fatalf("foreign commit: want ErrReservationConflict, got %v", err)
					}
				case modelState == StateReserved:
					if err != nil {
						rt.Fatalf("commit RESERVED: unexpected error %v", err)
					}
					modelState = StateActive
				default:
					if !errors.Is(err, ErrReservationConflict) {
						rt.Fatalf("commit non-RESERVED: want ErrReservationConflict, got %v", err)
					}
				}
			case "release":
				_, err := s.Release(ctx, key, actor)
				switch {
				case modelState == never:
					if !errors.Is(err, ErrReservationNotFound) {
						rt.Fatalf("release unknown: want ErrReservationNotFound, got %v", err)
					}
				case foreign:
					if !errors.Is(err, ErrReservationConflict) {
						rt.Fatalf("foreign release: want ErrReservationConflict, got %v", err)
					}
				default:
					if err != nil {
						rt.Fatalf("release: unexpected error %v", err)
					}
					modelState = StateReleased
				}
			case "bind":
				_, err := s.BindContainerName(ctx, key, actor, "ctr")
				switch {
				case modelState == never:
					if !errors.Is(err, ErrReservationNotFound) {
						rt.Fatalf("bind unknown: want ErrReservationNotFound, got %v", err)
					}
				case foreign:
					if !errors.Is(err, ErrReservationConflict) {
						rt.Fatalf("foreign bind: want ErrReservationConflict, got %v", err)
					}
				default:
					// Bind does not change the lifecycle state; the model state is
					// unchanged whether the bind takes (first time) or is refused
					// (already bound). Either outcome is acceptable here; the
					// dedicated bind cases cover write-once.
				}
			}

			// The store's observed state must match the model whenever a row exists.
			row, err := s.LookupSession(ctx, key)
			if modelState == never {
				if !errors.Is(err, ErrReservationNotFound) {
					rt.Fatalf("model says never-reserved but store has a row: %v / %+v", err, row)
				}
				continue
			}
			if err != nil {
				rt.Fatalf("lookup: unexpected error %v", err)
			}
			if row.State != modelState {
				rt.Fatalf("state drift: model=%v store=%v", modelState, row.State)
			}
		}
	})
}

// TestProperty_QuotaNoOvercommit interleaves random +1 and -1 charges against a
// single cell with a fixed limit and checks the cell never exceeds the limit,
// never goes negative, that a positive charge is refused exactly when it would
// overflow, and that a negative charge is never refused.
func TestProperty_QuotaNoOvercommit(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		s := newPropStore()

		limit := int64(rapid.IntRange(0, 8).Draw(rt, "limit"))
		key := QuotaKey{Dim: DimConcurrentSessions, Identity: propOwner}

		var model int64
		steps := rapid.IntRange(1, 60).Draw(rt, "steps")
		for i := 0; i < steps; i++ {
			delta := int64(rapid.SampledFrom([]int{-3, -1, 1, 2}).Draw(rt, "delta"))
			got, err := s.Charge(ctx, key, delta, limit)

			if delta < 0 {
				// A release is never refused and saturates at zero.
				if err != nil {
					rt.Fatalf("negative charge refused: %v", err)
				}
				model += delta
				if model < 0 {
					model = 0
				}
				if got != model {
					rt.Fatalf("release value drift: model=%d store=%d", model, got)
				}
				continue
			}

			// Positive charge: refused exactly when it would overflow the limit.
			if model+delta > limit {
				if !errors.Is(err, ErrQuotaExceeded) {
					rt.Fatalf("overflow charge: want ErrQuotaExceeded, got %v (model=%d delta=%d limit=%d)",
						err, model, delta, limit)
				}
				// Refused: the cell is unchanged.
				read, rerr := s.ReadQuota(ctx, key)
				if rerr != nil {
					rt.Fatalf("read after refusal: %v", rerr)
				}
				if read != model {
					rt.Fatalf("refused charge changed the cell: model=%d store=%d", model, read)
				}
				continue
			}

			if err != nil {
				rt.Fatalf("in-limit charge refused: %v (model=%d delta=%d limit=%d)", err, model, delta, limit)
			}
			model += delta
			if got != model {
				rt.Fatalf("charge value drift: model=%d store=%d", model, got)
			}
			if model > limit {
				rt.Fatalf("model exceeded limit: model=%d limit=%d", model, limit)
			}
			if model < 0 {
				rt.Fatalf("model went negative: model=%d", model)
			}
		}
	})
}

// TestProperty_DenyMonotone sets a random deny posture, then checks a Reserve is
// refused exactly when the key matches the posture, with the global kill-switch
// taking precedence over a per-session denylist (the documented fail-closed
// order), and that a refused Reserve leaves no row.
func TestProperty_DenyMonotone(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		ctx := context.Background()
		s := newPropStore()

		global := rapid.Bool().Draw(rt, "global")
		keys := []string{"x", "y", "z"}
		denied := make(map[string]bool)
		for _, k := range keys {
			if rapid.Bool().Draw(rt, "deny_"+k) {
				denied[k] = true
				if err := s.SetDeny(ctx, DenyEntry{Scope: ScopeSession, Key: k}); err != nil {
					rt.Fatalf("SetDeny session %q: %v", k, err)
				}
			}
		}
		if global {
			if err := s.SetDeny(ctx, DenyEntry{Scope: ScopeGlobal}); err != nil {
				rt.Fatalf("SetDeny global: %v", err)
			}
		}

		for _, k := range keys {
			_, err := s.Reserve(ctx, k, propOwner)
			switch {
			case global:
				// The kill-switch refuses every key and takes precedence.
				if !errors.Is(err, ErrKillSwitchEngaged) {
					rt.Fatalf("reserve under kill-switch %q: want ErrKillSwitchEngaged, got %v", k, err)
				}
			case denied[k]:
				if !errors.Is(err, ErrSessionDenied) {
					rt.Fatalf("reserve of denied key %q: want ErrSessionDenied, got %v", k, err)
				}
			default:
				if err != nil {
					rt.Fatalf("reserve of allowed key %q: unexpected error %v", k, err)
				}
			}

			// A refused Reserve must leave no row; an allowed one a RESERVED row.
			row, lerr := s.LookupSession(ctx, k)
			if err != nil {
				if !errors.Is(lerr, ErrReservationNotFound) {
					rt.Fatalf("refused reserve of %q left a row: %v / %+v", k, lerr, row)
				}
			} else {
				if lerr != nil || row.State != StateReserved {
					rt.Fatalf("allowed reserve of %q missing RESERVED row: %v / %+v", k, lerr, row)
				}
			}
		}
	})
}
