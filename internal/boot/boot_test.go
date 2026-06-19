// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package boot_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/boot"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fixedInstant anchors the injected FakeClock so every boot reads time through
// the one deterministic seam and runs are reproducible.
var fixedInstant = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// owner is the host-derived identity AdmitCreate reserves against in these
// tests. A request-supplied id would be a hint; this stands in for the
// host-resolved authority a Phase-3 ingress derives.
var owner = state.Identity{Tenant: "tenant-a", Caller: "caller-1"}

// newInMem builds a fresh in-memory Store backed by a fresh FakeClock anchored
// at fixedInstant, mirroring the statetest fixture so the sequencer is exercised
// against the same Store contract both legs satisfy.
func newInMem() (state.Store, state.Clock) {
	clk := state.NewFakeClock(fixedInstant)
	return state.NewInMemory(clk), clk
}

// faultStore is a Store whose LoadDeny fails with a wrapped ErrStoreUnavailable
// to drive the fail-closed boot leg. Every other method panics: a fail-closed
// boot must abort at LoadDeny and never call them.
type faultStore struct {
	state.Store // nil embedded interface: any un-overridden call panics, catching an unexpected reach past LoadDeny
}

func (faultStore) LoadDeny(context.Context) ([]state.DenyEntry, error) {
	return nil, fmt.Errorf("dial tcp 127.0.0.1:5432: connect: connection refused: %w", state.ErrStoreUnavailable)
}

// Test_Boot_Ordering pins the single ordering invariant: the deny posture is
// loaded BEFORE readiness flips, and the (stubbed) bind hook is reachable only
// after the load. Ready() is false before Boot and true after a clean Boot, and
// the onReady hook fires exactly once, strictly after readiness is ready.
func Test_Boot_Ordering(t *testing.T) {
	t.Parallel()
	store, clk := newInMem()
	seq := boot.New(store, clk)

	if ready, reason := seq.Ready(); ready {
		t.Fatalf("Ready() = true before Boot; want false (reason was %q)", reason)
	}

	// The bind hook records the readiness observed at the moment it ran. The
	// invariant is that bind is reachable only after readiness is ready.
	var bindFired bool
	var readyAtBind bool
	seq.SetOnReady(func(context.Context) error {
		bindFired = true
		readyAtBind, _ = seq.Ready()
		return nil
	})

	if err := seq.Boot(context.Background()); err != nil {
		t.Fatalf("Boot() returned error on a clean store: %v", err)
	}

	if ready, reason := seq.Ready(); !ready {
		t.Fatalf("Ready() = false after a clean Boot; want true (reason was %q)", reason)
	}
	if !bindFired {
		t.Fatal("onReady (bind stub) never fired after a clean Boot")
	}
	if !readyAtBind {
		t.Fatal("onReady (bind stub) ran while readiness was still not-ready; bind must be reachable only after the deny posture is durable")
	}
}

// Test_Boot_FailClosed_StoreUnavailable proves the fail-closed leg: a store
// whose LoadDeny reports ErrStoreUnavailable leaves the daemon not-ready, aborts
// Boot with ErrNotReady (and the underlying store sentinel), and never reaches
// the bind hook.
func Test_Boot_FailClosed_StoreUnavailable(t *testing.T) {
	t.Parallel()
	seq := boot.New(faultStore{}, state.NewFakeClock(fixedInstant))

	var bindFired bool
	seq.SetOnReady(func(context.Context) error {
		bindFired = true
		return nil
	})

	err := seq.Boot(context.Background())
	if err == nil {
		t.Fatal("Boot() returned nil on an unreachable store; want a fail-closed error")
	}
	if !errors.Is(err, boot.ErrNotReady) {
		t.Fatalf("Boot() error does not match boot.ErrNotReady: %v", err)
	}
	if !errors.Is(err, state.ErrStoreUnavailable) {
		t.Fatalf("Boot() error does not preserve state.ErrStoreUnavailable cause: %v", err)
	}
	if ready, _ := seq.Ready(); ready {
		t.Fatal("Ready() = true after a fail-closed Boot; want false")
	}
	if bindFired {
		t.Fatal("bind hook fired despite a fail-closed Boot; the listener must never bind when the store is unavailable")
	}
}

// Test_AdmitCreate_KillSwitchFirst is the end-to-end kill-switch-first refusal
// through the real Store: after a clean Boot (which engaged ScopeGlobal),
// AdmitCreate is refused with state.ErrKillSwitchEngaged and writes no row (the
// no-orphan property — LookupSession returns ErrReservationNotFound).
func Test_AdmitCreate_KillSwitchFirst(t *testing.T) {
	t.Parallel()
	store, clk := newInMem()
	seq := boot.New(store, clk)

	if err := seq.Boot(context.Background()); err != nil {
		t.Fatalf("Boot() returned error: %v", err)
	}

	err := seq.AdmitCreate(context.Background(), "k", owner)
	if err == nil {
		t.Fatal("AdmitCreate() succeeded with the kill-switch engaged; want a refusal")
	}
	if !errors.Is(err, state.ErrKillSwitchEngaged) {
		t.Fatalf("AdmitCreate() error does not match state.ErrKillSwitchEngaged: %v", err)
	}

	// No-orphan: the refused create wrote no reservation row.
	if _, lookErr := store.LookupSession(context.Background(), "k"); !errors.Is(lookErr, state.ErrReservationNotFound) {
		t.Fatalf("LookupSession after a refused create = %v; want ErrReservationNotFound (no orphan row)", lookErr)
	}
}

// Test_AdmitCreate_NegativeControl proves the refusal is caused by the engaged
// posture, not an unconditional branch: a Sequencer built without the boot
// kill-switch admits the create and a RESERVED row exists afterward.
func Test_AdmitCreate_NegativeControl(t *testing.T) {
	t.Parallel()
	store, clk := newInMem()
	seq := boot.New(store, clk, boot.WithoutBootKillSwitch())

	if err := seq.Boot(context.Background()); err != nil {
		t.Fatalf("Boot() returned error: %v", err)
	}

	if err := seq.AdmitCreate(context.Background(), "k", owner); err != nil {
		t.Fatalf("AdmitCreate() refused with no kill-switch engaged: %v", err)
	}

	row, lookErr := store.LookupSession(context.Background(), "k")
	if lookErr != nil {
		t.Fatalf("LookupSession after an admitted create: %v; want a row", lookErr)
	}
	if row.State != state.StateReserved {
		t.Fatalf("admitted create row state = %v; want StateReserved", row.State)
	}
}

// Test_AdmitCreate_DenyAllUntilLoaded pins the DENY-ALL-until-loaded default:
// AdmitCreate before Boot is refused fail-closed (ErrNotReady), never a silent
// allow, so a create cannot slip through the un-loaded boot window.
func Test_AdmitCreate_DenyAllUntilLoaded(t *testing.T) {
	t.Parallel()
	store, clk := newInMem()
	seq := boot.New(store, clk)

	err := seq.AdmitCreate(context.Background(), "k", owner)
	if err == nil {
		t.Fatal("AdmitCreate() before Boot succeeded; want a fail-closed refusal")
	}
	if !errors.Is(err, boot.ErrNotReady) {
		t.Fatalf("AdmitCreate() before Boot error does not match boot.ErrNotReady: %v", err)
	}

	// And it wrote no row.
	if _, lookErr := store.LookupSession(context.Background(), "k"); !errors.Is(lookErr, state.ErrReservationNotFound) {
		t.Fatalf("LookupSession after a pre-Boot refused create = %v; want ErrReservationNotFound", lookErr)
	}
}

// Test_Healthz_ThreeStates calls the /healthz handler with httptest (no
// listener) in each of the three readiness states and asserts the status code
// and body substring, the readiness contract a Phase-3 ingress mounts unchanged.
func Test_Healthz_ThreeStates(t *testing.T) {
	t.Parallel()

	t.Run("not ready before Boot", func(t *testing.T) {
		t.Parallel()
		store, clk := newInMem()
		seq := boot.New(store, clk)
		code, body := callHealthz(seq.Healthz())
		if code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d before Boot; want 503", code)
		}
		if !strings.Contains(body, "not yet loaded") {
			t.Fatalf("body = %q before Boot; want it to contain %q", body, "not yet loaded")
		}
	})

	t.Run("ready after a clean Boot", func(t *testing.T) {
		t.Parallel()
		store, clk := newInMem()
		seq := boot.New(store, clk)
		if err := seq.Boot(context.Background()); err != nil {
			t.Fatalf("Boot(): %v", err)
		}
		code, body := callHealthz(seq.Healthz())
		if code != http.StatusOK {
			t.Fatalf("status = %d after a clean Boot; want 200", code)
		}
		// Exact match, not Contains: "ready" is a substring of the not-ready
		// body "not ready: ...", so a substring check would not distinguish the
		// ready state from a not-ready one.
		if body != "ready" {
			t.Fatalf("body = %q after a clean Boot; want exactly %q", body, "ready")
		}
	})

	t.Run("not ready after a fault-store Boot", func(t *testing.T) {
		t.Parallel()
		seq := boot.New(faultStore{}, state.NewFakeClock(fixedInstant))
		if err := seq.Boot(context.Background()); err == nil {
			t.Fatal("Boot() returned nil on an unreachable store; want a fail-closed error")
		}
		code, body := callHealthz(seq.Healthz())
		if code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d after a fault-store Boot; want 503", code)
		}
		if !strings.Contains(body, "state store unavailable") {
			t.Fatalf("body = %q after a fault-store Boot; want it to contain %q", body, "state store unavailable")
		}
	})
}

// callHealthz drives an http.HandlerFunc with a recorder (no network) and
// returns the status code and the body.
func callHealthz(h http.HandlerFunc) (int, string) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h(rec, req)
	return rec.Code, rec.Body.String()
}
