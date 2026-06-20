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
