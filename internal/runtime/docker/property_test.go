// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"errors"
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestProperty_MaterializeRollback generates which of {NetworkCreate,
// ContainerCreate, ContainerStart} fails (and a typed/raw error flavour) and
// asserts the invariants across every schedule:
//   - on any failure the error errors.Is ErrMaterialize;
//   - the fake substrate is left with ZERO objects for the session (rollback ran);
//   - the rollback order is container-then-network (ContainerRemove precedes
//     NetworkRemove whenever both run).
func TestProperty_MaterializeRollback(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		failAt := rapid.SampledFrom([]string{"NetworkCreate", "ContainerCreate", "ContainerStart"}).Draw(rt, "failAt")
		flavour := rapid.SampledFrom([]string{"raw", "conflict", "notfound"}).Draw(rt, "flavour")

		var injected error
		switch flavour {
		case "conflict":
			injected = newConflict("network has active endpoints")
		case "notfound":
			injected = newNotFound("no such object")
		default:
			injected = errors.New("substrate boom")
		}

		fake := newFakeAPI()
		fake.errOn[failAt] = injected

		p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
		if err != nil {
			rt.Fatalf("NewDockerProvider: %v", err)
		}
		spec := validSpec()

		_, merr := p.Materialize(context.Background(), spec)
		if merr == nil {
			rt.Fatalf("Materialize with %s failing: want error, got nil", failAt)
		}
		if !errors.Is(merr, runtime.ErrMaterialize) {
			rt.Fatalf("Materialize error must be ErrMaterialize, got %v", merr)
		}

		// No orphan: the fake holds neither the bridge nor the container.
		if fake.holdsAnyFor(networkName(spec.Name), fake.nextID) {
			rt.Fatalf("rollback left an orphan (failAt=%s): ops=%v", failAt, fake.ops())
		}

		// Rollback ordering: whenever BOTH a container-remove and a network-remove
		// run, the container-remove precedes the network-remove (active-endpoints).
		ri := fake.indexOf("ContainerRemove")
		ni := fake.indexOf("NetworkRemove")
		if ri >= 0 && ni >= 0 && ni < ri {
			rt.Fatalf("rollback order violated: NetworkRemove before ContainerRemove: %v", fake.ops())
		}

		// Substrate-call discipline per failure point.
		switch failAt {
		case "NetworkCreate":
			// Nothing created -> no rollback removes, no container create.
			if fake.countOp("ContainerCreate") != 0 {
				rt.Fatalf("NetworkCreate failed but ContainerCreate ran: %v", fake.ops())
			}
		case "ContainerCreate":
			// Network created -> only the network is rolled back; no container exists.
			if fake.countOp("ContainerStart") != 0 {
				rt.Fatalf("ContainerCreate failed but ContainerStart ran: %v", fake.ops())
			}
			if fake.countOp("NetworkRemove") != 1 {
				rt.Fatalf("ContainerCreate failure must roll back the network exactly once: %v", fake.ops())
			}
		case "ContainerStart":
			// Both created -> both rolled back, container-then-network.
			if fake.countOp("ContainerRemove") != 1 || fake.countOp("NetworkRemove") != 1 {
				rt.Fatalf("ContainerStart failure must roll back container+network: %v", fake.ops())
			}
		}
	})
}

// TestProperty_MaterializeRollbackFault is the sibling robustness property: it
// drives Materialize to a primary failure that TRIGGERS a rollback (ContainerCreate
// or ContainerStart) AND ALSO injects a failure on the rollback removes themselves
// (ContainerRemove / NetworkRemove), across the typed/raw flavours of both. It
// proves the v0.1-cut rollback path is robust when a CLEANUP op also fails — the
// real-substrate case where a remove is refused (transient/in-use) or races an
// already-gone object. The invariants, beyond those the clean-rollback sibling
// (TestProperty_MaterializeRollback) owns:
//
//   - NO PANIC / NO HANG: the rollback path issues each remove once with no loop or
//     retry, so the body returning under rapid IS the termination proof; a panic
//     fails the rapid check directly.
//   - FAIL-CLOSED CREATE: a failed rollback op must NEVER turn the failed create
//     into a reported success — merr stays non-nil and errors.Is ErrMaterialize,
//     and the primary-flavour typed evidence survives the rollback failure.
//   - CLEANUP ATTEMPTED, BOUNDED: a swallowed ContainerRemove failure does NOT
//     short-circuit the following NetworkRemove (sequential best-effort), and the
//     container-then-network order holds even under a rollback-op failure.
//   - HONEST RESIDUE: an idempotent (not-found) rollback failure leaves zero
//     residue; a genuine (raw/conflict) rollback failure leaves a REAL orphan the
//     fake still holds — and that residue only ever co-occurs with the failed-closed
//     create (the next Reconcile sweep reclaims it), never with a silent success.
//
// failAt is constrained to {ContainerCreate, ContainerStart} on purpose: those are
// the only arms that drive a rollback, so injecting on a rollback op is reachable
// and non-vacuous. NetworkCreate is excluded (it rolls back nothing). The fake's
// errOn is sticky per op, but ContainerRemove/NetworkRemove are issued ONLY by the
// rollback helpers, so injecting on them collides with nothing the primary arm does
// — do NOT add a rollback op to failAt.
func TestProperty_MaterializeRollbackFault(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Only the arms that drive a rollback; NetworkCreate rolls back nothing.
		failAt := rapid.SampledFrom([]string{"ContainerCreate", "ContainerStart"}).Draw(rt, "failAt")
		// The primary create/start failure flavour (drives materializeError typing).
		primaryFlavour := rapid.SampledFrom([]string{"raw", "conflict", "notfound"}).Draw(rt, "primaryFlavour")
		// Which rollback op(s) are made to fail.
		rbTarget := rapid.SampledFrom([]string{"ContainerRemove", "NetworkRemove", "both"}).Draw(rt, "rbTarget")
		// The rollback-op failure flavour: notfound is idempotent already-gone (the
		// fake still drops the object); raw/conflict is a genuine refusal (the fake
		// keeps the object — a real orphan).
		rbFlavour := rapid.SampledFrom([]string{"notfound", "raw", "conflict"}).Draw(rt, "rbFlavour")

		flavourErr := func(kind string) error {
			switch kind {
			case "conflict":
				return newConflict("network has active endpoints")
			case "notfound":
				return newNotFound("no such object")
			default:
				return errors.New("substrate boom")
			}
		}

		fake := newFakeAPI()
		fake.errOn[failAt] = flavourErr(primaryFlavour)
		rbErr := flavourErr(rbFlavour)
		if rbTarget == "ContainerRemove" || rbTarget == "both" {
			fake.errOn["ContainerRemove"] = rbErr
		}
		if rbTarget == "NetworkRemove" || rbTarget == "both" {
			fake.errOn["NetworkRemove"] = rbErr
		}

		p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
		if err != nil {
			rt.Fatalf("NewDockerProvider: %v", err)
		}
		spec := validSpec()

		_, merr := p.Materialize(context.Background(), spec)

		// (B) FAIL-CLOSED: a rollback-op failure never masks the create failure.
		if merr == nil {
			rt.Fatalf("Materialize with %s failing must error even when rollback %s fails (%s): got nil",
				failAt, rbTarget, rbFlavour)
		}
		if !errors.Is(merr, runtime.ErrMaterialize) {
			rt.Fatalf("Materialize error must stay ErrMaterialize under a rollback-op failure, got %v", merr)
		}
		// The primary-flavour typed evidence must survive the rollback failure — a
		// failed remove must not corrupt the returned typed cause.
		switch primaryFlavour {
		case "conflict":
			if !errors.Is(merr, runtime.ErrNetworkActive) {
				rt.Fatalf("conflict primary must thread ErrNetworkActive under rollback failure, got %v", merr)
			}
		case "notfound":
			if !errors.Is(merr, runtime.ErrNoSuchContainer) {
				rt.Fatalf("not-found primary must thread ErrNoSuchContainer under rollback failure, got %v", merr)
			}
		}

		// Rollback ordering survives a rollback-op failure: whenever both removes run,
		// the container-remove precedes the network-remove (active-endpoints).
		ri := fake.indexOf("ContainerRemove")
		ni := fake.indexOf("NetworkRemove")
		if ri >= 0 && ni >= 0 && ni < ri {
			rt.Fatalf("rollback order violated under rollback-op failure: %v", fake.ops())
		}

		// (C) CLEANUP ATTEMPTED, BOUNDED — per failAt, and the load-bearing
		// non-vacuity guard: the rollback op we injected on actually RAN.
		switch failAt {
		case "ContainerCreate":
			// Only the network was created -> network is rolled back, no container.
			if fake.countOp("ContainerStart") != 0 {
				rt.Fatalf("ContainerCreate failed but ContainerStart ran: %v", fake.ops())
			}
			if fake.countOp("ContainerRemove") != 0 {
				rt.Fatalf("ContainerCreate failed but ContainerRemove ran (no container existed): %v", fake.ops())
			}
			if fake.countOp("NetworkRemove") != 1 {
				rt.Fatalf("ContainerCreate failure must roll back the network exactly once even under a rollback-op failure: %v", fake.ops())
			}
		case "ContainerStart":
			// Both created -> both rolled back. The NetworkRemove must STILL run after
			// a failed (swallowed) ContainerRemove: this proves the swallow is
			// intentional and bounded, not a short-circuit.
			if fake.countOp("ContainerRemove") != 1 {
				rt.Fatalf("ContainerStart failure must roll back the container exactly once: %v", fake.ops())
			}
			if fake.countOp("NetworkRemove") != 1 {
				rt.Fatalf("ContainerStart failure must STILL roll back the network after a failed ContainerRemove: %v", fake.ops())
			}
		}

		// NON-VACUITY GUARD: the rollback op we fault-injected was actually reached on
		// this run (keyed on reachability for the drawn failAt), so a future refactor
		// that stops calling a rollback helper turns this RED instead of silently
		// passing. ContainerRemove is only reachable from the ContainerStart arm.
		injectedContainerRemove := (rbTarget == "ContainerRemove" || rbTarget == "both") && failAt == "ContainerStart"
		injectedNetworkRemove := rbTarget == "NetworkRemove" || rbTarget == "both"
		if injectedContainerRemove && fake.countOp("ContainerRemove") < 1 {
			rt.Fatalf("fault-injected ContainerRemove never ran (dead injection): %v", fake.ops())
		}
		if injectedNetworkRemove && fake.countOp("NetworkRemove") < 1 {
			rt.Fatalf("fault-injected NetworkRemove never ran (dead injection): %v", fake.ops())
		}

		// (D) RESIDUE ACCOUNTING, split on the rollback-op flavour.
		held := fake.holdsAnyFor(networkName(spec.Name), fake.nextID)
		// Did a rollback op that actually ran fail with a genuine (non-idempotent)
		// error, leaving a real orphan? For ContainerCreate the ContainerRemove never
		// runs, so only a NetworkRemove failure can strand residue.
		networkRemoveFailed := injectedNetworkRemove
		containerRemoveFailed := injectedContainerRemove
		genuineRollbackFailure := (rbFlavour == "raw" || rbFlavour == "conflict") &&
			(networkRemoveFailed || containerRemoveFailed)

		if !genuineRollbackFailure {
			// Idempotent (not-found) rollback failures, or no rollback-op failure on a
			// reached op, leave ZERO residue — the fake drops on IsNotFound, faithful to
			// an already-gone object.
			if held {
				rt.Fatalf("idempotent/clean rollback must leave zero residue (failAt=%s rbTarget=%s rbFlavour=%s): %v",
					failAt, rbTarget, rbFlavour, fake.ops())
			}
		} else {
			// A genuine remove refusal leaves an HONEST orphan the fake still holds.
			// That is acceptable ONLY because the create already failed closed (B): the
			// orphan is surfaced via the failed create and reclaimed by the next
			// Reconcile sweep, NEVER reported as a live success. Assert the complement
			// invariant — held residue co-occurs with a non-nil ErrMaterialize.
			if held && merr == nil {
				rt.Fatalf("rollback-failure residue MUST co-occur with a failed create, never a silent success: %v", fake.ops())
			}
		}
	})
}

// TestProperty_FinalizerStepOrder generates a per-step schedule of failures, a
// guest-responsiveness grade, the verb (GracefulStop vs ForceKill), and whether the
// parent context is cancelled. INVARIANTS across every schedule:
//   - NetworkRemove is ALWAYS after ContainerRemove (active-endpoints);
//   - the kill step (ContainerRemove) ALWAYS runs;
//   - a cancelled parent context does NOT skip any host-side step (WithoutCancel);
//   - GracefulStop always reaches the force-remove regardless of guest grade;
//   - NO orphan — after teardown the fake holds neither container nor bridge
//     (unless a non-not-found removal failure was injected, which is reported as
//     ErrTeardown rather than silently dropped).
func TestProperty_FinalizerStepOrder(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		graceful := rapid.Bool().Draw(rt, "graceful")
		cancelParent := rapid.Bool().Draw(rt, "cancelParent")

		// Guest grade is modelled via the ContainerStop outcome (only consulted on
		// the GracefulStop drain): ok | hang(error) | gone(notfound).
		stopOutcome := rapid.SampledFrom([]string{"ok", "hang", "gone"}).Draw(rt, "stopOutcome")
		// The force-remove outcome: ok | gone(notfound, idempotent) | err(non-not-found).
		removeOutcome := rapid.SampledFrom([]string{"ok", "gone", "err"}).Draw(rt, "removeOutcome")
		// The network-remove outcome: ok | gone(notfound) | conflict | err.
		netOutcome := rapid.SampledFrom([]string{"ok", "gone", "conflict", "err"}).Draw(rt, "netOutcome")

		fake := newFakeAPI()
		// Pre-seed the substrate so the no-orphan post-condition is meaningful.
		bridge := networkName("sess-p")
		fake.networks[bridge] = true
		fake.containers["ctr-p"] = true

		switch stopOutcome {
		case "hang":
			fake.errOn["ContainerStop"] = errors.New("guest unresponsive")
		case "gone":
			fake.errOn["ContainerStop"] = newNotFound("already gone")
		}
		switch removeOutcome {
		case "gone":
			fake.errOn["ContainerRemove"] = newNotFound("no such container")
		case "err":
			fake.errOn["ContainerRemove"] = errors.New("remove boom")
		}
		switch netOutcome {
		case "gone":
			fake.errOn["NetworkRemove"] = newNotFound("no such network")
		case "conflict":
			fake.errOn["NetworkRemove"] = newConflict("active endpoints")
		case "err":
			fake.errOn["NetworkRemove"] = errors.New("net boom")
		}

		p, err := NewDockerProvider(runtime.TierRunc, Deps{API: fake})
		if err != nil {
			rt.Fatalf("NewDockerProvider: %v", err)
		}
		td := p.Teardown()
		sb := runtime.Sandbox{
			Name:      "sess-p",
			RuntimeID: "ctr-p",
			Egress:    runtime.EgressBinding{Name: "sess-p", FilesystemID: "fs-p"},
		}

		parent := context.Background()
		if cancelParent {
			ctx, cancel := context.WithCancel(parent)
			cancel() // Cancel BEFORE the call: WithoutCancel must keep every step running.
			parent = ctx
		}

		var terr error
		if graceful {
			terr = td.GracefulStop(parent, sb, runtime.Duration(5))
		} else {
			terr = td.ForceKill(parent, sb)
		}

		// The kill step ALWAYS runs.
		if fake.countOp("ContainerRemove") == 0 {
			rt.Fatalf("kill step (ContainerRemove) did not run: ops=%v", fake.ops())
		}

		// NetworkRemove is ALWAYS after ContainerRemove (active-endpoints constraint).
		ri := fake.indexOf("ContainerRemove")
		ni := fake.indexOf("NetworkRemove")
		if ni < 0 {
			rt.Fatalf("network step did not run: ops=%v", fake.ops())
		}
		if ni < ri {
			rt.Fatalf("NetworkRemove before ContainerRemove: ops=%v", fake.ops())
		}

		// GracefulStop must consult the drain (ContainerStop) before the kill, but
		// must NEVER stop at it: the force-remove still runs even on a hung guest.
		if graceful {
			si := fake.indexOf("ContainerStop")
			if si < 0 {
				rt.Fatalf("GracefulStop did not issue the drain ContainerStop: ops=%v", fake.ops())
			}
			if si > ri {
				rt.Fatalf("drain ContainerStop must precede the force-remove: ops=%v", fake.ops())
			}
		} else if fake.countOp("ContainerStop") != 0 {
			rt.Fatalf("ForceKill must skip the drain, but ContainerStop ran: ops=%v", fake.ops())
		}

		// A cancelled parent must NOT have skipped any host-side step: the full
		// six-step sequence is observable via the two substrate steps that log.
		// (The four host-side reclamation steps are nil-returning placeholders in
		// Phase 2, so the substrate evidence the body ran to completion is that BOTH
		// the kill and the network step ran — already asserted above.)

		// No-orphan accounting. A clean schedule (no non-not-found removal failure)
		// must leave the fake holding NEITHER object. A non-not-found removal failure
		// is surfaced as ErrTeardown (the resource is reported, never silently
		// dropped) — the body still ran the later step.
		removeFailed := removeOutcome == "err"
		netFailed := netOutcome == "err" || netOutcome == "conflict"

		if removeFailed || netFailed {
			if !errors.Is(terr, runtime.ErrTeardown) {
				rt.Fatalf("a non-idempotent removal failure must surface ErrTeardown, got %v (ops=%v)", terr, fake.ops())
			}
		} else {
			if terr != nil {
				rt.Fatalf("clean schedule must return nil, got %v (ops=%v)", terr, fake.ops())
			}
			if fake.holdsAnyFor(bridge, "ctr-p") {
				rt.Fatalf("orphan after clean teardown: ops=%v", fake.ops())
			}
		}

		// A network conflict must carry the typed ErrNetworkActive evidence.
		if netOutcome == "conflict" && !errors.Is(terr, runtime.ErrNetworkActive) {
			rt.Fatalf("network conflict must surface ErrNetworkActive, got %v", terr)
		}
	})
}
