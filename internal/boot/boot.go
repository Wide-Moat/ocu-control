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
// What this package proves (and only this):
//
//   - Ordering: Ready() is false until LoadDeny returns nil; the readiness flip
//     (and the listener bind that gates on it) is reachable only after the deny
//     posture is loaded-and-durable.
//   - Fail-closed: LoadDeny returning ErrStoreUnavailable (or a store that
//     failed to construct) leaves readiness at not-ready and aborts boot, so no
//     create slips through an un-loaded window.
//   - Kill-switch-first as a TRANSIENT gate: AdmitCreate refuses every create
//     until LoadDeny completes and readiness flips ready — a pre-load refusal
//     lifted by the load itself, never a fabricated boot-time global deny. Once
//     loaded, the SERVED posture is exactly the operator-authored deny LoadDeny
//     restored: AdmitCreate delegates the create to Store.Reserve, so if an
//     operator engaged a deployment-wide DENY-ALL before the last shutdown the
//     restored ScopeGlobal entry refuses the create with the typed
//     state.ErrKillSwitchEngaged read back from real durable state; on a store
//     with no operator deny the create is admitted normally. The refusal, when
//     it fires, originates in operator-authored durable state — not a hardcoded
//     boot-time branch.
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

	// onReady, when non-nil, is invoked exactly once immediately after readiness
	// flips to ready and before Boot returns. It is the bind seam: the listener
	// bind hangs off this hook so the ordering ("bind reachable only after deny
	// posture durable") is structural, not incidental. It is nil in production
	// composition that opens no listener, and an order-recording probe in tests.
	onReady func(context.Context) error
}

// New builds a Sequencer over an already-constructed Store and Clock. It does
// no I/O: the same clk must be the one the Store was constructed with so the
// whole boot reads time through one seam. The returned Sequencer is not-ready
// until Boot succeeds. Boot LOADS the durable deny posture and SERVES exactly
// what it restored; it never fabricates a deny — a deployment-wide DENY-ALL is
// operator-authored durable state, not a boot-time default (NFR-SEC-01).
func New(store state.Store, clk state.Clock) *Sequencer {
	return &Sequencer{
		store: store,
		clk:   clk,
	}
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
//  2. Flip readiness to ready — strictly after the posture is loaded-and-durable
//     — and run the onReady (bind) hook.
//
// Before Boot returns nil, AdmitCreate refuses fail-closed (the transient
// not-loaded gate), so no create can slip through the un-loaded window. Boot
// engages NO deny of its own: the deployment-wide DENY-ALL is operator-authored
// durable state, so the SERVED posture is exactly what LoadDeny restored — a
// global deny an operator engaged before the last shutdown is restored (every
// Reserve still refuses), and a clean store admits creates (NFR-SEC-01).
func (s *Sequencer) Boot(ctx context.Context) error {
	// Step 1: durable read of the deny posture. This is the gate the whole
	// ordering invariant turns on, and it IS the authority for the served
	// posture: a successful read restores whatever operator-authored deny state
	// the Store holds, and Reserve consults that same Store, so the restored
	// posture is enforced implicitly — a separately-fabricated boot-time deny
	// would impersonate an operator who triggered nothing.
	if _, err := s.store.LoadDeny(ctx); err != nil {
		// Fail closed. Classify store-unavailability explicitly for the
		// readiness reason; any other load error is equally fail-closed.
		s.state.Store(int32(stateStoreUnavailable))
		return fmt.Errorf("%w: load deny posture: %w", ErrNotReady, err)
	}

	// Step 2: only now is the posture loaded-and-durable. Flip readiness to
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

// AdmitCreate is the kill-switch-first create gate. It is the seam a per-request
// ingress path calls; the daemon also calls it once for the -create-on-start
// ordering smoke hook. It refuses fail-closed before the deny posture is loaded
// (the transient not-loaded gate) so no create slips through the un-loaded boot
// window, then delegates the create to Store.Reserve. When an operator engaged a
// deployment-wide DENY-ALL that LoadDeny restored, Reserve returns
// state.ErrKillSwitchEngaged and writes no row (the no-orphan property), and
// AdmitCreate surfaces that typed error wrapped — the refusal originates in the
// operator-authored durable state, not here. On a store with no operator deny,
// Reserve admits the create normally (requirement 3, NFR-SEC-01).
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
