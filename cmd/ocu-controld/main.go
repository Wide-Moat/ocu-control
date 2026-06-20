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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/boot"
	"github.com/Wide-Moat/ocu-control/internal/controlrpc"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/mountcfg"
	"github.com/Wide-Moat/ocu-control/internal/provisioning"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtime/docker"
	"github.com/Wide-Moat/ocu-control/internal/runtime/k8s"
	"github.com/Wide-Moat/ocu-control/internal/state"
	"github.com/Wide-Moat/ocu-control/internal/state/postgres"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

// Sentinel refusals. The e2e smoke greps stable substrings of these, so the
// wording is load-bearing: do not reword without updating scripts/e2e-smoke.sh.
var (
	errRequiredFlagMissing    = errors.New("required flag missing or invalid")
	errUnknownRuntimeTier     = errors.New("unknown runtime tier")
	errUnknownProvider        = errors.New("unknown runtime provider")
	errUnknownWorkloadProfile = errors.New("unknown workload profile")
	errUnknownJWTAlg          = errors.New("unknown jwt signing algorithm")
	errKillSwitchFirst        = errors.New("kill-switch engaged before listener bind: create refused (NFR-SEC-01)")
)

// knownRuntimeTiers and knownRuntimeProviders are the closed enumerations the
// daemon accepts. An unrecognized value is refused, never coerced to a
// default — a tier/provider must be chosen explicitly (PRD: runtime-tier is
// deployment-wide, never per-request; the provider is selected behind the
// RuntimeProvider seam).
var (
	knownRuntimeTiers     = map[string]bool{"runc": true, "gvisor": true, "firecracker": true}
	knownRuntimeProviders = map[string]bool{"docker": true, "k8s": true}
	// knownWorkloadProfiles is the closed enumeration the admission matrix is keyed
	// on. An omitted profile is caught as a missing required flag; an unknown one is
	// refused here, never coerced to a permissive default — a defaulted profile would
	// silently widen the admission matrix (the must-fix discipline mirroring
	// -runtime-tier).
	knownWorkloadProfiles = map[string]bool{"trusted_operator": true, "internal_workforce": true, "untrusted": true}
	// knownJWTAlgs is the closed enumeration of Storage-JWT signing algorithms. The
	// default is eddsa (NFR-SEC-11, Ed25519-family); es256 is supported for a
	// deployment matching the mount-config schema example. An unknown alg is refused,
	// never coerced (the alg is written per-key in the keyring, not silently picked).
	knownJWTAlgs = map[string]bool{"eddsa": true, "es256": true}
)

func main() {
	// The root context is cancelled on SIGINT/SIGTERM, so a host-initiated daemon
	// stop unwinds the serve loops, runs the deferred listener Close (unlinking the
	// operator socket), and returns cleanly. This is the HOST-side daemon stop —
	// distinct from the per-session runtime finalizer, which runs below the seam
	// under context.WithoutCancel and is never cancelled by this signal. The
	// kill-switch-first boot ordering and the bind-after-ready invariant are
	// untouched: the signal only cancels the serve phase that runs strictly AFTER a
	// successful Boot.
	//
	// stop() is called BEFORE os.Exit (not via defer): a deferred call does not run
	// after os.Exit, so the signal handler is unregistered explicitly on both the
	// clean and the error path.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	stop()
	if err != nil {
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
		// Thin client: dial the already-running daemon's operator /healthz over the
		// SAME Unix socket the serving path binds (re-derived from -operator-listen, so
		// probe and server agree on the path) and exit 0 iff it answers 200. It does
		// NOT boot the Store or any listener.
		return healthCheck(ctx, cfg.operatorListen)
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
// passed, then composes the lifecycle layer and the two-listener ingress and
// binds both listeners — but ONLY off the boot readiness hook, strictly after
// Boot has loaded the durable deny posture and engaged the deployment-wide
// kill-switch. An unreachable store at boot is fail-closed: serve returns and
// binds nothing.
//
// The composition wires the deployment-fixed profile and tier into the lifecycle
// Manager (neither is per-request), constructs the kill-switch Engine and both
// ingress adapters, and hands the SINGLE OperatorSeam to the operator adapter
// ALONE — the gateway adapter is given no seam and has no import path to the mint,
// so the kill-switch is unreachable from the gateway as a compile fact.
//
// With -create-on-start (the smoke hook), a create is presented through the real
// Sequencer.AdmitCreate path BEFORE any bind hook is registered: the engaged
// kill-switch makes Store.Reserve refuse with state.ErrKillSwitchEngaged, which
// serve re-wraps under errKillSwitchFirst so the operator-facing refusal still
// names NFR-SEC-01. Because this path returns before the bind hook is installed,
// the create-on-start refusal binds no socket — the e2e smoke asserts exactly
// that no socket exists on the refusal.
func serve(ctx context.Context, cfg config) error {
	clk := state.SystemClock()

	store, err := openStore(ctx, cfg.stateDSN, clk)
	if err != nil {
		// Store construction failed (e.g. an unreachable Postgres). This is a
		// fail-closed boot abort before any readiness flip or bind.
		return fmt.Errorf("boot: open state store: %w", err)
	}

	// The create-on-start smoke hook is a PRE-BIND refusal: it must flow through the
	// real boot + Store path and refuse against the engaged kill-switch WITHOUT
	// registering the listener-bind hook, so no socket is ever bound on the refusal.
	// It runs its own minimal Boot (no onReady) and returns the NFR-SEC-01 refusal.
	if cfg.create {
		return serveCreateOnStart(ctx, store, clk)
	}

	tier, err := runtimeTierOf(cfg.runtimeTier)
	if err != nil {
		return err
	}
	profile, err := workloadProfileOf(cfg.workloadProfile)
	if err != nil {
		return err
	}

	// Storage-JWT custody, FAIL-CLOSED at boot: a missing or garbage signing key
	// aborts the daemon BEFORE any listener binds (there is no daemon-default key).
	// The shared Revoker is recorded against by every Storage-JWT mint (via the
	// Signer) and consulted by the below-seam finalizer step-1, so one index serves
	// both the create path and teardown.
	signer, revoker, err := buildSigner(cfg, clk)
	if err != nil {
		return fmt.Errorf("boot: load storage-jwt signer: %w", err)
	}

	// The docker finalizer step 3 scrubs the per-session handoff root under the SAME
	// base the handoff Stager (compose, below) writes under, so the host-owned
	// credential tree is reclaimed on teardown. The base is a deployment-fixed host
	// config value, never a per-request body field.
	provider, err := providerOf(cfg.runtimeProvider, tier, revoker, handoffBase)
	if err != nil {
		return err
	}

	// Durable audit custody, FAIL-CLOSED at boot: -audit-sink names the append-only
	// OCSF spine every privileged action is hash-chained into BEFORE it is
	// acknowledged. A real path is backed by a durable, fsync-on-write file writer; an
	// unopenable path aborts the daemon here, before any listener binds, rather than
	// booting with a silently-discarded trail. The single opt-out (=none/=null) is the
	// NullSink, behind a loud WARN that the trail is non-durable.
	auditWriter, err := buildAuditWriter(cfg.auditSink)
	if err != nil {
		return fmt.Errorf("boot: open audit sink: %w", err)
	}
	// Close the writer on the way out so the final fsync/flush runs after the serve
	// loops have drained. A NullSink Close is a no-op.
	defer func() { _ = auditWriter.Close() }()

	mgr, eng := compose(store, clk, provider, profile, tier, signer, auditWriter, cfg)

	// The single operator capability: minted ONCE and handed to the operator
	// adapter ALONE. The gateway adapter is constructed with no seam.
	seam := ingress.NewOperatorSeam()
	seq := boot.New(store, clk)

	opListener := operator.NewListener(socketPathOf(cfg.operatorListen), operator.Deps{
		Manager:  mgr,
		Engine:   eng,
		Healthz:  seq.Healthz(),
		Resolver: operator.NewPeerCredResolver(nil),
		Seam:     seam, // the operator adapter alone holds the seam
	})
	gwListener := gateway.NewListener(tcpAddrOf(cfg.gatewayListen), gateway.Deps{
		Manager:  mgr,
		Resolver: gateway.NewCertSANResolver(nil),
		// No TLSConfig wired in this phase: the gateway binds plain TCP whose
		// connections carry no verified SAN, so every Resolve fails closed (a
		// clearly-stubbed, fail-closed posture). No OperatorSeam is passed.
	})

	// The bind hook runs from inside Boot, strictly AFTER readiness flips to ready
	// (the deny posture is loaded-and-durable). The reconciler sweep runs first so a
	// crashed-mid-create orphan is reclaimed before traffic is admitted, then both
	// listeners bind and serve. Binding here makes "bind reachable only after deny
	// posture durable" structural, not incidental.
	seq.SetOnReady(func(hookCtx context.Context) error {
		if err := mgr.Reconcile(hookCtx); err != nil {
			// Belt-and-braces fence on top of the two shipped LiveSessions impls: if
			// the bound Store somehow does not support live-session enumeration, the
			// orphan-reclaim sweep cannot run, but a daemon on a host with no orphans
			// must still reach a serving state. Skip the reclaim with a loud WARN in
			// that single case ONLY; EVERY other reconcile error stays fail-closed (a
			// real substrate or store fault must never bind a half-reconciled daemon).
			if errors.Is(err, registry.ErrEnumerationUnsupported) {
				fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: state store does not support live-session enumeration; skipping orphan reclaim (NFR-SEC-01: no new authority granted, but crashed RESERVED rows are not reclaimed this boot)")
			} else {
				return fmt.Errorf("boot: reconcile orphans: %w", err)
			}
		}
		if err := opListener.Bind(); err != nil {
			return err
		}
		if err := gwListener.Bind(); err != nil {
			_ = opListener.Close()
			return err
		}
		return nil
	})

	if err := seq.Boot(ctx); err != nil {
		// Fail-closed: the deny posture could not be loaded/engaged (or a bind in the
		// readiness hook failed), so the daemon stays not-ready. Close anything that
		// did bind so the refusal leaves no half-open listener.
		_ = opListener.Close()
		_ = gwListener.Close()
		return err
	}

	// Both listeners are bound. Serve them until the process context is cancelled;
	// the first serve error (or a clean ctx shutdown returning nil) ends the daemon.
	return serveListeners(ctx, opListener, gwListener)
}

// serveCreateOnStart drives the kill-switch-first create smoke hook end-to-end
// through the real boot + Store path and refuses pre-bind. It registers NO
// readiness bind hook, so the refusal binds no socket — the e2e smoke asserts
// exactly that. The refusal's typed cause is state.ErrKillSwitchEngaged from the
// boot-engaged global posture; it is re-wrapped under errKillSwitchFirst so the
// load-bearing NFR-SEC-01 text holds.
func serveCreateOnStart(ctx context.Context, store state.Store, clk state.Clock) error {
	seq := boot.New(store, clk)
	if err := seq.Boot(ctx); err != nil {
		return err
	}
	owner := state.Identity{Tenant: "smoke-tenant", Caller: "smoke-caller"}
	if err := seq.AdmitCreate(ctx, "create-on-start", owner); err != nil {
		if errors.Is(err, state.ErrKillSwitchEngaged) {
			return fmt.Errorf("%w: %v", errKillSwitchFirst, err)
		}
		return err
	}
	// An admitted create here would be a kill-switch-first violation: unreachable
	// because Boot always engages the global posture.
	return errors.New("boot: create admitted despite kill-switch-first posture (invariant violated)")
}

// compose builds the lifecycle Manager and the kill-switch Engine over the shared
// Store, Clock, and Provider. The minimal-shelf collaborators — an in-tree
// handoff Stager, the OCSF chain audit sink over the NullSink default writer
// (chain computed in-process, nothing durably persisted by default), and a
// deployment Limits — are bound here. profile and tier are deployment-fixed and
// flow onto the Manager as fixed fields; CreateInput carries neither.
func compose(store state.Store, clk state.Clock, provider runtime.RuntimeProvider, profile admission.WorkloadProfile, tier runtime.RuntimeTier, signer *cred.Signer, auditWriter ocsf.EventWriter, cfg config) (*lifecycle.Manager, *killswitch.Engine) {
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, defaultLimits())
	stager := handoff.NewStager(handoffBase)
	// The real OCSF chain sink: it serializes each privileged audit.Record to a
	// faithful OCSF event, assigns a per-source monotonic sequence, and hash-chains
	// the spine — all on the success path, BEFORE the privileged action is
	// acknowledged (fail-closed). The durable writer is the one buildAuditWriter
	// resolved from -audit-sink: a real path is backed by the append-only fsync-on-
	// write FileSink, so a write failure denies the action (the fail-closed branch in
	// the lifecycle/kill-switch callers now actually fires); the explicit =none/=null
	// opt-out is the NullSink (compute-and-validate, persist-nothing). The writer slots
	// in behind the EventWriter contract with no change to any Emit call site.
	sink := ocsf.NewChainSink(clk, auditWriter, "control")

	// The advisory control-RPC dialer mints its per-dial exec JWT through the same
	// Storage-JWT custodian Signer (the narrow MintExecJWT seam, never the signing
	// key). When the Signer is absent (the Phase-3 minimal shelf) there is no exec-JWT
	// minter, so the dialer stays nil and the Destroy nudge is a clean no-op.
	var controlDialer lifecycle.ControlDialer
	if signer != nil {
		controlDialer = controlrpc.NewDialer(signer, 0)
	}

	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: custodian,
		Provider:  provider,
		Clock:     clk,
		Quota:     gate,
		Handoff:   stager,
		Audit:     sink,
		Profile:   profile,
		Tier:      tier,

		// Storage-JWT custody + mount-config provisioning. The Signer mints the weak
		// Storage-JWT (recording its jti on the shared Revoker); Push delivers the
		// rendered mount-config to the host-owned handoff bind before the mount client
		// boots. ServiceURL/CACertPEM and the host-chosen mount defaults are
		// deployment-fixed; the storage scope is host-derived, never a body hint.
		Signer:        signer,
		Push:          provisioning.NewPusher(),
		ServiceURL:    cfg.serviceURL,
		CACertPEM:     readCACertPEM(cfg.caCert),
		MountDefaults: defaultMountDefaults(),
		StorageScope:  defaultStorageScope(),
		ControlDialer: controlDialer,
	})
	eng := killswitch.NewEngine(store, custodian, provider, clk, sink)
	return mgr, eng
}

// drainTimeout bounds how long serveListeners waits for both Serve loops to
// unwind after a signal-driven ctx cancel before it closes the listeners and
// returns anyway. A wedged Serve goroutine can never strand the daemon stop: the
// deferred Close runs and the process exits regardless. It is generous because a
// clean drain is near-instant (each Serve closes its own *http.Server on
// ctx.Done) and the bound exists only as a backstop.
const drainTimeout = 10 * time.Second

// serveListeners runs both bound listeners until ctx is cancelled or a Serve loop
// errors. A SIGINT/SIGTERM cancels ctx, both Serve loops unwind, and this returns
// nil (a signal stop is not an error); a Serve error before any signal is
// returned as-is. On EITHER exit it closes both listeners — operator first, so the
// privileged socket is unlinked before the gateway port is released — so neither
// socket survives the daemon, and it waits (bounded by drainTimeout) for both
// Serve goroutines to finish so the close ordering is observable rather than racing
// the goroutines' own teardown.
func serveListeners(ctx context.Context, op *operator.Listener, gw *gateway.Listener) error {
	errCh := make(chan error, 2)
	go func() { errCh <- op.Serve(ctx) }()
	go func() { errCh <- gw.Serve(ctx) }()

	closeBoth := func() {
		// Operator-first teardown: the privileged Unix socket is unlinked before the
		// gateway TCP port is released, mirroring the bind ordering (operator before
		// gateway) so a restart re-binds the operator plane cleanly.
		_ = op.Close()
		_ = gw.Close()
	}

	// Wait for the first event: a clean ctx-driven shutdown (the signal path) or the
	// first non-nil serve error. On the signal path the Serve loops are already
	// unwinding (each closes its own server on ctx.Done); on the error path the
	// other loop is stopped by closeBoth.
	var (
		serveErr error
		drained  int // Serve goroutines that have already returned a value.
	)
	select {
	case <-ctx.Done():
		// Signal-driven stop: not an error. Both loops are still running; the bounded
		// drain below waits for them after closeBoth.
	case serveErr = <-errCh:
		// A serve loop failed (or cleanly exited) before any signal; one goroutine has
		// already reported, so only the other remains to drain.
		drained = 1
	}

	// Stop accepting on both listeners, then wait (bounded) for the remaining Serve
	// goroutines to return so the drain is complete before the daemon exits.
	closeBoth()
	drain, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainTimeout)
	defer cancel()
	for drained < 2 {
		select {
		case <-errCh:
			drained++
		case <-drain.Done():
			// A wedged Serve goroutine must not strand the daemon stop: both listeners
			// are already closed, so return regardless.
			return serveErr
		}
	}
	return serveErr
}

// handoffBase is the host-owned directory under which the handoff Stager writes
// each per-session 0700 root. It is a fixed minimal-shelf path; a deployment may
// override it in a later phase.
const handoffBase = "/run/ocu-control/handoff"

// defaultLimits is the minimal-shelf deployment quota policy. The values are
// conservative non-zero ceilings so the create path charges real counters; a
// deployment tunes them in a later phase.
func defaultLimits() quota.Limits {
	return quota.Limits{
		ConcurrentSessionsPerTenant: 64,
		MCPCallsPerMinPerTenant:     600,
		StorageGBPerTenant:          100,
		EgressBytesPerDayPerTenant:  1 << 40, // 1 TiB/day
		CreateRatePerCallerPerMin:   30,
	}
}

// storageTTL is the fixed, SHORT Storage-JWT window (a deployment parameter, not a
// sourced value). There is no refresh path; a fresh token before expiry is a new
// mint, never an exp bump.
const storageTTL = 15 * time.Minute

// buildSigner loads the Storage-JWT signer from the -jwt-signing-key MOUNT path,
// FAIL-CLOSED: a missing or garbage key (or an unknown alg) is an error the caller
// turns into a boot abort BEFORE any listener binds. It constructs the shared
// monotonic Revoker on the same injected Clock and attaches it to the Signer, so
// every Storage-JWT mint records its jti against the host-derived session key the
// below-seam finalizer revokes by. iss/aud are CONFIG-DRIVEN/provisional and flow
// from the flags, never hardcoded.
func buildSigner(cfg config, clk state.Clock) (*cred.Signer, *cred.Revoker, error) {
	alg, err := algOf(cfg.jwtAlg)
	if err != nil {
		return nil, nil, err
	}
	signer, err := cred.LoadSignerFromMount(cfg.jwtSigningKey, clk, cred.Config{
		Alg:             alg,
		StorageIssuer:   cfg.storageIssuer,
		StorageAudience: cfg.storageAudience,
		ExecIssuer:      cfg.execIssuer,
		ExecAudience:    cfg.execAudience,
		StorageTTL:      storageTTL,
	})
	if err != nil {
		return nil, nil, err
	}
	revoker := cred.NewRevoker(clk)
	signer.UseRevoker(revoker)
	return signer, revoker, nil
}

// algOf maps the validated -jwt-alg string to the cred.Alg. The string was already
// enum-checked in validate(); an unexpected value here is a hard internal error,
// never a silent default.
func algOf(s string) (cred.Alg, error) {
	switch s {
	case "eddsa":
		return cred.AlgEdDSA, nil
	case "es256":
		return cred.AlgES256, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnknownJWTAlg, s)
	}
}

// auditWriter is the durable-emit seam the chain sink writes to, plus the Close the
// daemon runs on shutdown to flush the final fsync. The FileSink satisfies it; the
// NullSink is wrapped in a no-op closer so the opt-out path shares the same type.
type auditWriter interface {
	ocsf.EventWriter
	Close() error
}

// nullCloser adapts the stateless ocsf.NullSink to the auditWriter shape: its Close
// is a no-op so the explicit -audit-sink=none/=null opt-out flows through the same
// build-and-close path as the durable FileSink.
type nullCloser struct{ ocsf.NullSink }

// Close is a no-op: NullSink holds no file handle to flush.
func (nullCloser) Close() error { return nil }

// auditSinkNone is the explicit, case-insensitive opt-out: -audit-sink=none (or
// =null) selects the non-durable NullSink behind a loud startup WARN. It is the ONLY
// way to run without a durable trail — a real path is NEVER silently discarded.
var auditSinkNone = map[string]bool{"none": true, "null": true}

// buildAuditWriter resolves -audit-sink into the durable-emit writer the chain sink
// hash-chains into. A real path is backed by the append-only, fsync-on-write,
// single-writer FileSink, opened FAIL-CLOSED: an unopenable path (e.g. an unwritable
// directory) is an error the caller turns into a boot abort BEFORE any listener
// binds, so the daemon never runs with a path it would silently discard. The only
// non-durable option is the explicit =none/=null opt-out, which selects the NullSink
// and emits a LOUD startup WARN that the audit trail is non-durable. validate()
// already rejects an EMPTY -audit-sink as a missing required flag, so this never
// defaults a discarded sink.
func buildAuditWriter(sink string) (auditWriter, error) {
	if auditSinkNone[strings.ToLower(sink)] {
		fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: -audit-sink="+sink+" selects the NULL audit writer: the OCSF hash-chain is computed in-process but NOTHING is durably persisted. Every privileged action's fail-closed-on-audit deny is therefore NOT backed by durable storage. Use a writable file path for a durable, tamper-evident trail.")
		return nullCloser{}, nil
	}
	fs, err := ocsf.OpenFileSink(sink)
	if err != nil {
		return nil, err
	}
	return fs, nil
}

// readCACertPEM reads the CA certificate PEM from the -ca-cert path for rendering
// into every mount-config. An empty path or an unreadable file yields an empty
// string: the mount-config render then refuses fail-closed at create time
// (ErrBadCACert) rather than the daemon aborting at boot — a deployment without
// storage provisioning configured still boots and serves the lifecycle base path.
func readCACertPEM(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// defaultMountDefaults is the minimal-shelf, schema-validated per-mount posture the
// substrate-neutral MountIntent does not carry. The values are built through the
// validating constructors; a panic here is a programmer error (a constant that does
// not match the frozen $def), never a runtime path. A deployment tunes them later.
func defaultMountDefaults() mountcfg.MountDefaults {
	mode, err := mountcfg.NewVfsCacheMode("writes")
	if err != nil {
		panic(fmt.Sprintf("ocu-controld: invalid default vfs_cache_mode: %v", err))
	}
	size, err := mountcfg.NewByteSize("512M")
	if err != nil {
		panic(fmt.Sprintf("ocu-controld: invalid default vfs_cache_max_size: %v", err))
	}
	dir, err := mountcfg.NewOctal("0700")
	if err != nil {
		panic(fmt.Sprintf("ocu-controld: invalid default dir_perms: %v", err))
	}
	file, err := mountcfg.NewOctal("0600")
	if err != nil {
		panic(fmt.Sprintf("ocu-controld: invalid default file_perms: %v", err))
	}
	return mountcfg.MountDefaults{VfsCacheMode: mode, VfsCacheMaxSize: size, DirPerms: dir, FilePerms: file}
}

// defaultStorageScope is the minimal-shelf, deployment-fixed Storage-JWT scope. It
// is HOST-DERIVED (deployment config + the host-derived session identity), never a
// request-body hint (NFR-SEC-43). Workspace/Org are provisional alongside iss/aud;
// the intent is write (the RW sink posture) and downloadable defaults false.
func defaultStorageScope() lifecycle.StorageScope {
	return lifecycle.StorageScope{
		Intent:       cred.IntentWrite,
		Downloadable: false,
	}
}

// runtimeTierOf maps the validated -runtime-tier string to the runtime.RuntimeTier
// the provider is constructed bound to. The string was already enum-checked in
// validate(); an unexpected value here is a hard internal error, never a default.
func runtimeTierOf(s string) (runtime.RuntimeTier, error) {
	switch s {
	case "runc":
		return runtime.TierRunc, nil
	case "gvisor":
		return runtime.TierGvisor, nil
	case "firecracker":
		return runtime.TierFirecracker, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnknownRuntimeTier, s)
	}
}

// workloadProfileOf maps the validated -workload-profile string to the
// admission.WorkloadProfile the Manager holds as a fixed field. The string was
// already enum-checked in validate(); an unexpected value here is a hard internal
// error, never a default — a defaulted profile would silently widen the matrix.
func workloadProfileOf(s string) (admission.WorkloadProfile, error) {
	switch s {
	case "trusted_operator":
		return admission.ProfileTrustedOperator, nil
	case "internal_workforce":
		return admission.ProfileInternalWorkforce, nil
	case "untrusted":
		return admission.ProfileUntrusted, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnknownWorkloadProfile, s)
	}
}

// providerOf constructs the RuntimeProvider behind the seam from the validated
// -runtime-provider string, bound to the deployment-wide tier. docker builds the
// real env-configured Docker provider; k8s returns the (NotImplemented) k8s
// provider. The tier is fixed at construction and can never be weakened by a
// request. stagerBase is the deployment-fixed handoff root the docker finalizer
// step 3 scrubs (base/<SessionName>); it is the SAME base the handoff.Stager is
// constructed with, so teardown re-derives the credential-bearing handoff tree
// purely from the host-derived SessionName.
func providerOf(name string, tier runtime.RuntimeTier, revoker docker.Revoker, stagerBase string) (runtime.RuntimeProvider, error) {
	switch name {
	case "docker":
		// The shared Revoker is the below-seam finalizer step-1 (revoke session JWT)
		// target; the same instance the Signer records mints against. StagerBase is the
		// finalizer step-3 (handoff-root scrub) base — the SAME path the handoff Stager
		// writes under, so teardown reclaims the host-owned credential tree.
		p, err := docker.NewDockerProvider(tier, docker.Deps{Revoker: revoker, StagerBase: stagerBase})
		if err != nil {
			return nil, fmt.Errorf("boot: construct docker provider: %w", err)
		}
		return p, nil
	case "k8s":
		return k8s.New(), nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownProvider, name)
	}
}

// socketPathOf strips a unix:// scheme from the operator endpoint, yielding the
// filesystem socket path net.Listen("unix", ...) takes. A bare path is returned
// unchanged.
func socketPathOf(endpoint string) string {
	if p, ok := strings.CutPrefix(endpoint, "unix://"); ok {
		return p
	}
	return endpoint
}

// tcpAddrOf strips a tcp:// scheme from the gateway endpoint, yielding the
// host:port net.Listen("tcp", ...) takes. A bare host:port is returned unchanged.
func tcpAddrOf(endpoint string) string {
	if a, ok := strings.CutPrefix(endpoint, "tcp://"); ok {
		return a
	}
	return endpoint
}
