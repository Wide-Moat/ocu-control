// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// ocu-controld — the one-per-deployment control plane daemon (component-02).
//
// This is the scaffold entry point. It does not yet run sessions: the session
// registry, admission matrix, kill-switch engine, Storage-JWT signer, and the
// per-session executor supervisor land as the internal/ packages are built.
// What it does today is validate its own invocation and refuse a bad one
// pre-bind with a typed error — the observable behaviour scripts/e2e-smoke.sh
// asserts against the real binary:
//
//  1. a missing required flag is named in the refusal text;
//  2. an unknown -runtime-tier / -runtime-provider is refused, never
//     silently defaulted;
//  3. KILL-SWITCH-FIRST: a create request is refused loudly before any
//     listener binds (the denylist/kill-switch DENY-ALL engages first), and
//     no socket is ever bound on a refusal.
//
// The real lifecycle wiring (host-dials-guest control channel, teardown
// finalizer, audit emission) replaces the placeholder run() as the
// implementation PRs land.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-control/internal/boot"
	"github.com/Wide-Moat/ocu-control/internal/state"
	"github.com/Wide-Moat/ocu-control/internal/state/postgres"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

// Sentinel refusals. The e2e smoke greps stable substrings of these, so the
// wording is load-bearing: do not reword without updating scripts/e2e-smoke.sh.
var (
	errRequiredFlagMissing = errors.New("required flag missing or invalid")
	errUnknownRuntimeTier  = errors.New("unknown runtime tier")
	errUnknownProvider     = errors.New("unknown runtime provider")
	errKillSwitchFirst     = errors.New("kill-switch engaged before listener bind: create refused (NFR-SEC-01)")
)

// knownRuntimeTiers and knownRuntimeProviders are the closed enumerations the
// daemon accepts. An unrecognized value is refused, never coerced to a
// default — a tier/provider must be chosen explicitly (PRD: runtime-tier is
// deployment-wide, never per-request; the provider is selected behind the
// RuntimeProvider seam).
var (
	knownRuntimeTiers     = map[string]bool{"runc": true, "gvisor": true, "firecracker": true}
	knownRuntimeProviders = map[string]bool{"docker": true}
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-controld:", err)
		os.Exit(1)
	}
}

// run parses argv and either handles an informational mode (-version,
// -health-check) or validates the serving invocation and runs the kill-switch-
// first boot. It returns an error on any refusal; main maps that to exit 1. No
// real ingress binds in this phase, so a refusal trivially leaves no socket.
func run(ctx context.Context, args []string) error {
	cfg, mode, err := parse(args)
	if err != nil {
		return err
	}

	switch mode {
	case modeVersion:
		fmt.Printf("ocu-controld %s\n", version)
		return nil
	case modeHealthCheck:
		// Self-probe placeholder: with no ops listener wired yet there is
		// nothing to dial, so report not-serving rather than a false green.
		return errors.New("health-check: ops listener not yet implemented in this scaffold")
	}

	if err := validate(cfg); err != nil {
		return err
	}
	return serve(ctx, cfg)
}

// openStore selects the durable-state backend. The minimal-shelf default
// (empty DSN) is the in-memory Store, which cannot fail to construct. A
// non-empty DSN opens Postgres, which runs the idempotent migration and returns
// state.ErrStoreUnavailable fail-closed on an unreachable database. The single
// injected clk is the same one passed to the Sequencer, so the whole boot reads
// time through one seam.
func openStore(ctx context.Context, dsn string, clk state.Clock) (state.Store, error) {
	if dsn == "" {
		return state.NewInMemory(clk), nil
	}
	return postgres.Open(ctx, dsn, clk)
}

// serve runs the kill-switch-first boot sequence after the static gates have
// passed: it constructs one clock and the selected Store, builds the boot
// Sequencer, and runs Boot — which loads the durable deny posture and engages
// the deployment-wide kill-switch BEFORE any listener could bind. An
// unreachable store at boot is fail-closed: serve returns and binds nothing.
//
// With -create-on-start, a create is presented through the real
// Sequencer.AdmitCreate path. The engaged kill-switch makes Store.Reserve
// refuse with state.ErrKillSwitchEngaged, which serve re-wraps under
// errKillSwitchFirst so the operator-facing refusal still names NFR-SEC-01 —
// but the refusal now originates in a real Store read, not a hardcoded branch.
// AdmitCreate runs before the (stubbed) bind, so no socket exists at refusal.
//
// The actual two-listener ingress bind is a Phase-3 step; here it stays a stub
// reached only after a clean, create-free boot.
func serve(ctx context.Context, cfg config) error {
	clk := state.SystemClock()

	store, err := openStore(ctx, cfg.stateDSN, clk)
	if err != nil {
		// Store construction failed (e.g. an unreachable Postgres). This is a
		// fail-closed boot abort before any readiness flip or bind.
		return fmt.Errorf("boot: open state store: %w", err)
	}

	seq := boot.New(store, clk)
	if err := seq.Boot(ctx); err != nil {
		// Fail-closed: the deny posture could not be loaded/engaged, so the
		// daemon stays not-ready and binds nothing.
		return err
	}

	// The kill-switch-first create gate, flowing through the real Store. The
	// refusal's typed cause is state.ErrKillSwitchEngaged from the engaged
	// global posture; we re-wrap it so the load-bearing NFR-SEC-01 text holds.
	if cfg.create {
		owner := state.Identity{Tenant: "smoke-tenant", Caller: "smoke-caller"}
		if err := seq.AdmitCreate(ctx, "create-on-start", owner); err != nil {
			if errors.Is(err, state.ErrKillSwitchEngaged) {
				return fmt.Errorf("%w: %v", errKillSwitchFirst, err)
			}
			return err
		}
		// An admitted create here would be a kill-switch-first violation: this
		// branch is unreachable in Phase 1 because Boot always engages the
		// global posture.
		return errors.New("boot: create admitted despite kill-switch-first posture (invariant violated)")
	}

	// A real serve would bind the two ingress listeners here, mounting
	// seq.Healthz() on the operator listener. Phase 1 stops short of binding:
	// the listener wiring lands in Phase 3.
	return fmt.Errorf("listener bind not yet wired in this phase (deny posture engaged, tier=%s provider=%s)", cfg.runtimeTier, cfg.runtimeProvider)
}
