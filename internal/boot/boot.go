// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package boot is the kill-switch-first boot sequencer for ocu-controld. It
// owns the single Phase-1 ordering invariant the control plane must never
// violate: the durable deny posture is loaded and engaged BEFORE any listener
// binds and before any create is admitted, and an unreachable store at boot is
// fail-closed — the daemon stays not-ready, binds nothing, and admits no
// create (requirement 3, NFR-SEC-01).
//
// The sequencer is a thin policy layer over the state.Store seam: it does not
// open a database, dial a socket, or read the wall clock directly. Its
// collaborators — a Store and a Clock — are injected already-built from cmd/,
// so the whole boot path reads time through one seam and talks to durable
// state through one interface, and a unit test can exercise it with an
// in-memory store and a FakeClock exactly as the conformance suite does.
//
// What this package proves in Phase 1 (and only this):
//
//   - Ordering: Ready() is false until LoadDeny returns nil; the readiness flip
//     (and the Phase-3 listener bind that gates on it) is reachable only after
//     the deny posture is loaded-and-durable.
//   - Fail-closed: LoadDeny returning ErrStoreUnavailable (or a store that
//     failed to construct) leaves readiness at not-ready and aborts boot, so no
//     create slips through an un-loaded window.
//   - Kill-switch-first end-to-end: Boot engages a deployment-wide kill-switch
//     via the Store, and AdmitCreate delegates the create to Store.Reserve, so a
//     create presented at startup is refused with the typed
//     state.ErrKillSwitchEngaged read back from real durable state — not a
//     hardcoded branch.
//
// The ingress listeners, the admission matrix, quota, the RuntimeProvider, the
// Storage-JWT signer, and OCSF audit live in their own packages and are composed
// in cmd/ocu-controld; this package owns only the kill-switch-first ordering
// invariant and binds nothing itself.
package boot

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrNotReady is the fail-closed boot abort: the durable deny posture could not
// be loaded (the store was unreachable at boot), so the daemon must not bind a
// listener and must not admit a create. It wraps state.ErrStoreUnavailable, so
// a caller may match either this sentinel or the underlying store sentinel with
// errors.Is (requirement 3, NFR-SEC-01).
//
// The kill-switch create refusal is deliberately NOT a sentinel of this
// package: that refusal originates in the Store as state.ErrKillSwitchEngaged
// and is surfaced by AdmitCreate unchanged, so the typed error a create sees is
// the same one any per-request admission path will see in a later phase.
var ErrNotReady = errors.New("boot: not ready, deny posture not loaded (fail-closed)")

// readinessState is the lock-free readiness enum the /healthz handler reads
// concurrently. It starts at notLoaded and advances to exactly one terminal
// value: ready on a clean Boot, or storeUnavailable on a fail-closed Boot. It
// never moves backward and never returns to notLoaded.
type readinessState int32

const (
	// stateNotLoaded is the pre-Boot posture: the deny state has not yet been
	// loaded, so the daemon is not ready and AdmitCreate refuses fail-closed
	// (DENY-ALL-until-loaded).
	stateNotLoaded readinessState = iota
	// stateReady is set only after LoadDeny returns nil and the deny posture is
	// engaged. Only now may a listener bind.
	stateReady
	// stateStoreUnavailable is the fail-closed terminal: LoadDeny (or store
	// construction) reported the store unreachable, so the daemon stays
	// not-ready and binds nothing.
	stateStoreUnavailable
)

// Human-facing readiness reasons. These are the exact strings Ready() returns
// and the /healthz handler writes, so the Phase-1 readiness contract tests can
// assert them by substring.
const (
	reasonNotLoaded        = "deny posture not yet loaded"
	reasonReady            = "ready"
	reasonStoreUnavailable = "state store unavailable"
)

// Sequencer drives the kill-switch-first boot and exposes the readiness
// predicate the /healthz surface reports. It holds the injected Store and Clock
// and an atomic readiness state; construction touches neither the network nor
// the Store — it only wires already-built collaborators, so it is safe to
// build in a test with an in-memory or fault store and a FakeClock.
type Sequencer struct {
	store state.Store
	clk   state.Clock

	// state is the lock-free readiness enum the /healthz handler reads from a
	// concurrent goroutine. An atomic so a future bound listener can poll it
	// without coordinating with the boot goroutine.
	state atomic.Int32

	// engageKillSwitch records whether Boot engages the deployment-wide
	// kill-switch as the Phase-1 proven posture. It is true by default (the
	// honest Phase-1 demonstration of the kill-switch-first invariant); a test
	// builds a Sequencer with it false to prove the create refusal is caused by
	// the engaged posture, not by an unconditional branch.
	engageKillSwitch bool

	// onReady, when non-nil, is invoked exactly once immediately after readiness
	// flips to ready and before Boot returns. It is the Phase-3 bind seam: the
	// listener bind hangs off this hook so the ordering ("bind reachable only
	// after deny posture durable") is structural, not incidental. In Phase 1 it
	// is nil in production and an order-recording probe in tests.
	onReady func(context.Context) error
}

// Option configures a Sequencer at construction. The default (no options)
// engages the deployment-wide kill-switch at Boot — the Phase-1 proven posture
// the daemon ships with.
type Option func(*Sequencer)

// WithoutBootKillSwitch builds a Sequencer that does NOT engage the
// deployment-wide kill-switch at Boot. It exists for the negative-control test
// that proves the create refusal is caused by the engaged posture rather than
// an unconditional branch, and for a later phase that loads operator-authored
// deny state instead of the boot-time default. It is not used on the production
// boot path.
func WithoutBootKillSwitch() Option {
	return func(s *Sequencer) { s.engageKillSwitch = false }
}

// New builds a Sequencer over an already-constructed Store and Clock. It does
// no I/O: the same clk must be the one the Store was constructed with so the
// whole boot reads time through one seam. The returned Sequencer is not-ready
// until Boot succeeds, and it engages the deployment-wide kill-switch at Boot
// (the Phase-1 proven posture) unless WithoutBootKillSwitch is supplied.
func New(store state.Store, clk state.Clock, opts ...Option) *Sequencer {
	s := &Sequencer{
		store:            store,
		clk:              clk,
		engageKillSwitch: true,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SetOnReady installs the post-load readiness hook (the Phase-3 listener-bind
// seam). It must be called before Boot. The hook runs after readiness flips to
// ready; if it returns an error, Boot propagates it. In Phase 1 production
// leaves it unset (no listener binds); tests use it to assert ordering.
func (s *Sequencer) SetOnReady(fn func(context.Context) error) {
	s.onReady = fn
}

// Boot runs the kill-switch-first sequence:
//
//  1. LoadDeny — the durable read of the deny posture. Any error (notably
//     state.ErrStoreUnavailable) is fail-closed: readiness stays not-ready, the
//     state is set to store-unavailable, and Boot returns ErrNotReady. The
//     daemon must not proceed to bind.
//  2. Engage the deployment-wide kill-switch via SetDeny (the Phase-1 proven
//     posture), so a create at startup is refused against real durable state.
//  3. Flip readiness to ready — strictly after the posture is loaded-and-durable
//     — and run the onReady (bind) hook.
//
// Before Boot returns nil, AdmitCreate refuses fail-closed (DENY-ALL-until-
// loaded), so no create can slip through the un-loaded window.
func (s *Sequencer) Boot(ctx context.Context) error {
	// Step 1: durable read of the deny posture. This is the gate the whole
	// ordering invariant turns on. The loaded entries are not inspected here in
	// Phase 1 — a successful read is the evidence the posture is durable and
	// re-engageable; Reserve consults the same Store, so the posture is engaged
	// implicitly by being durable. A later phase walks the entries to mirror
	// operator-authored deny state into an in-memory fast path.
	if _, err := s.store.LoadDeny(ctx); err != nil {
		// Fail closed. Classify store-unavailability explicitly for the
		// readiness reason; any other load error is equally fail-closed.
		s.state.Store(int32(stateStoreUnavailable))
		return fmt.Errorf("%w: load deny posture: %w", ErrNotReady, err)
	}

	// Step 2: engage the deployment-wide kill-switch as the Phase-1 proven
	// posture. There is no operator ingress yet to author a denylist, so the
	// only honest way to demonstrate the kill-switch-first invariant end-to-end
	// this phase is to engage the global posture here, then refuse a create
	// against it through a real Store read. A later phase replaces this
	// unconditional SetDeny with operator-authored deny state; AdmitCreate does
	// not change.
	if s.engageKillSwitch {
		if err := s.store.SetDeny(ctx, state.DenyEntry{
			Scope:  state.ScopeGlobal,
			Reason: "kill-switch-first boot (NFR-SEC-01)",
			Since:  s.clk.Now(),
		}); err != nil {
			// A store that accepted LoadDeny but cannot persist the kill-switch
			// is not a deployment we may serve from: failing to engage the
			// posture is fail-closed exactly as a failed load is.
			s.state.Store(int32(stateStoreUnavailable))
			return fmt.Errorf("%w: engage kill-switch: %w", ErrNotReady, err)
		}
	}

	// Step 3: only now is the posture loaded-and-durable. Flip readiness to
	// ready, then run the bind hook. The flip strictly follows the successful
	// LoadDeny, so Ready() can only report true after the deny posture exists.
	s.state.Store(int32(stateReady))

	if s.onReady != nil {
		if err := s.onReady(ctx); err != nil {
			return fmt.Errorf("boot: post-ready hook failed: %w", err)
		}
	}
	return nil
}

// Ready reports whether the deny posture has been loaded-and-engaged and the
// daemon may admit traffic, plus a human-facing reason for /healthz. It is
// lock-free and safe to call concurrently with Boot. It returns false before
// Boot (deny posture not yet loaded) and false after a fail-closed Boot (state
// store unavailable); true only after a clean Boot.
func (s *Sequencer) Ready() (bool, string) {
	switch readinessState(s.state.Load()) {
	case stateReady:
		return true, reasonReady
	case stateStoreUnavailable:
		return false, reasonStoreUnavailable
	case stateNotLoaded:
		return false, reasonNotLoaded
	default:
		// The enum is closed; an unrecognized value is fail-closed not-ready.
		return false, reasonNotLoaded
	}
}

// AdmitCreate is the kill-switch-first create gate. It is the seam a Phase-3
// per-request ingress path will call; in Phase 1 the daemon calls it once for
// the -create-on-start smoke hook. It refuses fail-closed before the deny
// posture is loaded (DENY-ALL-until-loaded) so no create slips through the
// un-loaded boot window, then delegates the create to Store.Reserve. With the
// deployment-wide kill-switch engaged, Reserve returns
// state.ErrKillSwitchEngaged and writes no row (the no-orphan property), and
// AdmitCreate surfaces that typed error wrapped — the refusal originates in the
// Store, not here (requirement 3, NFR-SEC-01).
func (s *Sequencer) AdmitCreate(ctx context.Context, key string, owner state.Identity) error {
	if ready, reason := s.Ready(); !ready {
		// DENY-ALL-until-loaded: a create before the posture is durable is
		// refused fail-closed, never silently allowed.
		return fmt.Errorf("%w: admit create refused: %s", ErrNotReady, reason)
	}
	if _, err := s.store.Reserve(ctx, key, owner); err != nil {
		return fmt.Errorf("admit create refused: %w", err)
	}
	return nil
}

// Healthz returns the /healthz handler closure. It is a pure handler over the
// readiness predicate and binds no listener — Phase 1 opens no socket, so a
// Phase-3 ingress can mount this exact handler onto the operator listener with
// no change to the handler itself. It writes 200 "ready" when ready and 503
// "not ready: <reason>" otherwise. The readiness read is atomic, so the handler
// is safe to serve from a concurrent goroutine.
func (s *Sequencer) Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		ready, reason := s.Ready()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if ready {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, reasonReady)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "not ready: %s", reason)
	}
}
