// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// ocu-controld — the one-per-deployment control plane daemon (component-02).
//
// main wires SIGINT/SIGTERM into the root context, so a host-initiated stop
// unwinds the serve loops cleanly. run() dispatches the -version and
// -health-check informational modes, then validates the serving invocation and
// runs the kill-switch-first boot.
//
// serve() is the composition root. It opens the state.Store (in-memory or
// Postgres), runs Boot — which loads the durable deny posture (and serves exactly
// the operator-authored deny it restored) before any listener binds — constructs
// the Storage-JWT signer, the RuntimeProvider behind the seam, and the durable
// OCSF audit sink, composes the lifecycle Manager and the kill-switch Engine, and
// binds the operator and gateway listeners ONLY off the boot readiness hook (so a
// bind is reachable only after the deny posture is durable). It then serves until
// the signal-driven shutdown.
//
// Boot is fail-closed throughout: an unreachable store, a missing signing key,
// or an unopenable audit sink aborts before any listener binds. -create-on-start
// is the pre-bind kill-switch-first ORDERING smoke hook: a create presented
// BEFORE Boot loads the deny posture is refused by the transient not-loaded gate
// (NFR-SEC-01), then a create AFTER a clean Boot is admitted — all without
// registering the bind hook, so no socket is ever bound on the refusal.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/boot"
	"github.com/Wide-Moat/ocu-control/internal/controlrpc"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/guestexec"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/jwks"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	mcpkeypostgres "github.com/Wide-Moat/ocu-control/internal/mcpkey/postgres"
	"github.com/Wide-Moat/ocu-control/internal/mcpkeyset"
	"github.com/Wide-Moat/ocu-control/internal/metrics"
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
	errKillSwitchFirst        = errors.New("kill-switch-first: create before deny posture loaded refused (NFR-SEC-01)")
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
// Boot has loaded the durable deny posture (and restored exactly the
// operator-authored deny it holds). An unreachable store at boot is fail-closed:
// serve returns and binds nothing.
//
// The composition wires the deployment-fixed profile and tier into the lifecycle
// Manager (neither is per-request), constructs the kill-switch Engine and both
// ingress adapters, and hands the SINGLE OperatorSeam to the operator adapter
// ALONE — the gateway adapter is given no seam and has no import path to the mint,
// so the kill-switch is unreachable from the gateway as a compile fact.
//
// With -create-on-start (the smoke hook), a create is presented through the real
// Sequencer.AdmitCreate path BEFORE any bind hook is registered AND before Boot
// loads the deny posture: the transient not-loaded gate refuses it with
// boot.ErrNotReady, which serve re-wraps under errKillSwitchFirst so the
// operator-facing refusal still names NFR-SEC-01. The hook then loads the posture
// and confirms a clean-store create is admitted (the daemon is not inert). Because
// this path returns before the bind hook is installed, the create-on-start path
// binds no socket — the e2e smoke asserts exactly that no socket exists.
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

	// Exec-channel signing key, FAIL-CLOSED at boot when configured: the exec channel
	// (ADR-0024) verifies a Session JWT signed by a SEPARATE deployment-wide Ed25519
	// key (ADR-0013 key separation — never the Storage-JWT keyring). Its public half
	// is the guest's staged --auth-public-key verify file. -exec-signing-key UNSET
	// leaves execSigner nil, which disables the exec channel (the gateway exec verb
	// fail-closes); a SET but garbage key aborts boot before any listener binds.
	var execSigner *cred.ExecSigner
	if cfg.execSigningKey != "" {
		execSigner, err = cred.LoadExecSignerFromMount(cfg.execSigningKey)
		if err != nil {
			return fmt.Errorf("boot: load exec signing key: %w", err)
		}
	}

	// Storage-JWT JWKS artifact, FAIL-CLOSED at boot: when -jwks-path is set, render
	// the static JWKS document the deploy layer serves at the egress edge's
	// remote_jwks URI (ADR-0019 §35) so the edge can validate the weak Storage-JWT
	// via stock Envoy jwt_authn remote_jwks. An empty key set here is a fail-closed
	// boot abort — never a silently-written empty Set (which would make the edge
	// reject every token or mask a missing signer). -jwks-path unset is a clean
	// no-op: the minimal shelf may run without storage provisioning. This is a FILE
	// write, not a network surface — it adds NO third listener, so the two-listener
	// invariant (§39 / NFR-SEC-52) is unchanged. It is NOT gated on the listeners
	// binding (it must exist before the edge would fetch it), but it DOES abort the
	// boot closed on an empty set. v1 has no live rotation hook, so the render
	// trigger is boot/restart; a future live-rotation seam re-invokes WriteArtifact
	// over the same path to re-render the served document.
	if err := renderJWKSArtifact(cfg, signer); err != nil {
		return err
	}

	// Durable audit custody, FAIL-CLOSED at boot: -audit-sink names the append-only
	// OCSF spine every privileged action is hash-chained into BEFORE it is
	// acknowledged. A real path is backed by a durable, fsync-on-write file writer; an
	// unopenable path aborts the daemon here, before any listener binds, rather than
	// booting with a silently-discarded trail. The single opt-out (=none/=null) is the
	// NullSink, behind a loud WARN that the trail is non-durable.
	//
	// The audit sink is built BEFORE the runtime provider so the provider's teardown
	// finalizer can record its step-1 revoke outcome against the SAME durable spine
	// (via the revokeOutcomeAuditor below). This ordering does not touch the
	// kill-switch-first invariant: that is the Boot sequencer's durable deny posture,
	// loaded further down (boot.New / seq) and gated on the listener-bind hook — no
	// listener binds before it, and neither the provider nor the audit sink admits a
	// create.
	auditWriter, err := buildAuditWriter(cfg.auditSink)
	if err != nil {
		return fmt.Errorf("boot: open audit sink: %w", err)
	}
	// Close the writer on the way out so the final fsync/flush runs after the serve
	// loops have drained. A NullSink Close is a no-op.
	defer func() { _ = auditWriter.Close() }()

	// Build the chain sink RESUMED from the existing spine: a restart continues the
	// per-source monotonic sequence and prior-hash link rather than re-anchoring at
	// genesis (which would break the tamper-evidence spine). A decoupled tail records
	// an explicit chain-break marker before the spine continues; a boot-time verify
	// aborts if the existing file already fails the chain. All fail-closed at boot,
	// before any listener binds.
	sink, err := buildResumedChainSink(ctx, clk, auditWriter, cfg.auditSink)
	if err != nil {
		return fmt.Errorf("boot: resume audit chain: %w", err)
	}

	// The docker finalizer step 3 scrubs the per-session handoff root under the SAME
	// base the handoff Stager (compose, below) writes under, so the host-owned
	// credential tree is reclaimed on teardown. The base is a deployment-fixed host
	// config value, never a per-request body field. The revokeOutcomeAuditor wires
	// the finalizer step-1 revoke outcome onto the durable spine as destroy evidence.
	provider, err := providerOf(cfg.runtimeProvider, tier, revoker, handoffBase, cfg.egressNetwork, cfg.edgeHost, sink)
	if err != nil {
		return err
	}

	mgr, eng, custodian, collector, auditSink := compose(store, clk, provider, profile, tier, signer, execSigner, sink, cfg)

	// MCP API key surface, FAIL-CLOSED at boot: construct the Engine from a
	// Minter (crypto/rand), the selected RecordStore (Postgres when -state-dsn is
	// set; in-memory when empty — the same backend-select idiom as the state store),
	// the shared audit sink, and a re-render closure. The Engine is handed to the
	// operator adapter ALONE (the gateway adapter receives none). This mirrors the
	// JWKS wiring pattern: an optional -mcp-keyset-path, a fail-closed boot-load of
	// -mcp-key-file when the file exists, and a re-render closure that runs on
	// every create/revoke. The SAME chain sink that compose() wired into the Manager
	// and killswitch Engine is reused — one chain-linked spine for all operator ops.
	mcpKeyEngine, err := buildMCPKeyEngine(ctx, cfg, clk, auditSink)
	if err != nil {
		return fmt.Errorf("boot: build mcp-key engine: %w", err)
	}

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
		// The admin read-surface (ADR-0022): the read handler is given ONLY the
		// custodian's enriched read port and the deployment singletons — no seam, no
		// Manager, no Engine — so the read-only boundary holds structurally. The
		// /metrics scrape handler mounts the collector's exposition. Both are the
		// operator plane only; the gateway adapter receives neither.
		Reader:       custodian,
		Deployment:   operator.DeploymentInfo{RuntimeTier: cfg.runtimeTier, RuntimeProvider: cfg.runtimeProvider},
		Metrics:      collector.Handler(),
		MCPKeyEngine: mcpKeyEngine, // operator adapter alone; gateway adapter gets none
	})
	// Gateway mTLS server config, FAIL-CLOSED at boot when configured: with all
	// three -gateway-tls-* flags set, the gateway binds a real TLS 1.3 listener that
	// REQUIRES AND VERIFIES a client cert against the client-CA, so a connection's
	// verified SAN is the host-attested service identity. Unset (validate() already
	// enforced all-or-none) leaves gwTLS nil and the listener keeps the stubbed
	// plain-TCP posture (no verified SAN → every Resolve fails closed).
	gwTLS, err := buildGatewayTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("boot: load gateway mTLS config: %w", err)
	}
	gwListener := gateway.NewListener(tcpAddrOf(cfg.gatewayListen), gateway.Deps{
		Manager:   mgr,
		Resolver:  gateway.NewCertSANResolver(nil),
		TLSConfig: gwTLS,
		// When TLSConfig is nil the gateway binds plain TCP whose connections carry
		// no verified SAN, so every Resolve fails closed (a clearly-stubbed,
		// fail-closed posture). No OperatorSeam is passed.
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
		// Both listeners are bound and accepting: tell systemd the unit is ready.
		// This is the last step of the readiness hook, so READY=1 is sent only on a
		// clean boot — a bind failure above returns before this line and the daemon
		// never reports ready (under Type=notify systemd then times the start out, as
		// the unit intends). A no-op when not run under systemd.
		notifyReady()
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

// serveCreateOnStart drives the kill-switch-FIRST ORDERING smoke hook end-to-end
// through the real boot + Store path and binds NO socket — the e2e smoke asserts
// exactly that no listener exists on the refusal. It demonstrates the REAL
// kill-switch-first invariant: a create presented BEFORE Boot loads the durable
// deny posture is refused fail-closed by the transient not-loaded gate (the
// daemon grants no authority in the un-loaded window), and a create AFTER a clean
// Boot with no operator-authored deny is admitted normally — proving the daemon is
// not inert. The pre-load refusal's typed cause is boot.ErrNotReady; it is
// re-wrapped under errKillSwitchFirst so the load-bearing NFR-SEC-01 text holds.
func serveCreateOnStart(ctx context.Context, store state.Store, clk state.Clock) error {
	seq := boot.New(store, clk)
	owner := state.Identity{Tenant: "smoke-tenant", Caller: "smoke-caller"}

	// BEFORE Boot: the transient not-loaded gate refuses the create fail-closed, so
	// no create slips through the un-loaded window. This is the kill-switch-first
	// ordering the smoke proves — a refusal lifted by the load itself, never a
	// fabricated boot-time global deny.
	if err := seq.AdmitCreate(ctx, "create-on-start", owner); err == nil {
		return errors.New("boot: create admitted before the deny posture loaded (kill-switch-first ordering violated)")
	} else if !errors.Is(err, boot.ErrNotReady) {
		return err
	} else {
		// Re-wrap the pre-load refusal under the NFR-SEC-01 sentinel the smoke greps,
		// preserving the typed boot.ErrNotReady cause in the chain so a caller can
		// match either the operator-facing sentinel or the transient-gate cause.
		preLoad := fmt.Errorf("%w: %w", errKillSwitchFirst, err)
		// Now LOAD the durable posture and prove a clean-store create is admitted —
		// the daemon is not inert. A non-nil Boot is a fail-closed abort (surfaced
		// as-is); an operator-authored global deny restored by LoadDeny would refuse
		// the create below with state.ErrKillSwitchEngaged, which is the correct
		// durable-restore behaviour and also surfaced as-is.
		if err := seq.Boot(ctx); err != nil {
			return err
		}
		if err := seq.AdmitCreate(ctx, "create-on-start", owner); err != nil {
			return fmt.Errorf("boot: clean-boot create-on-start refused after load: %w", err)
		}
		// The ordering proof is the load-bearing smoke assertion: report the pre-load
		// refusal so the daemon exits 1 naming NFR-SEC-01, having also confirmed the
		// post-load admit succeeds (no socket was ever bound — no onReady hook ran).
		return preLoad
	}
}

// compose builds the lifecycle Manager and the kill-switch Engine over the shared
// Store, Clock, and Provider. The minimal-shelf collaborators — an in-tree
// handoff Stager, the OCSF chain audit sink over the NullSink default writer
// (chain computed in-process, nothing durably persisted by default), and a
// deployment Limits — are bound here. profile and tier are deployment-fixed and
// flow onto the Manager as fixed fields; CreateInput carries neither.
func compose(store state.Store, clk state.Clock, provider runtime.RuntimeProvider, profile admission.WorkloadProfile, tier runtime.RuntimeTier, signer *cred.Signer, execSigner *cred.ExecSigner, sink *ocsf.ChainSink, cfg config) (*lifecycle.Manager, *killswitch.Engine, *registry.Custodian, *metrics.Collector, audit.AuditSink) {
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, defaultLimits())
	// The metrics collector reads live state through the same custodian the admin
	// read-API uses, so the counts-by-state gauge reflects exactly the listed set. It
	// is handed to the Manager (which increments create/destroy and observes the
	// reserved->active start duration) and to the operator listener (which mounts its
	// /metrics scrape handler). It is purely observational — non-fatal everywhere.
	collector := metrics.NewCollector(custodian)
	stager := handoff.NewStager(handoffBase)
	// The OCSF chain sink is built and RESUMED in main() (buildResumedChainSink), where
	// the boot-edge I/O — reading the prior spine's tip, recording a chain-break on a
	// decoupled tail, and the boot-time chain verification — lives next to the boot's
	// context and error handling. compose stays a pure composition and receives the
	// ready sink, so a test injects a fake sink without touching this wiring.

	// The advisory control-RPC dialer and the guest exec driver both mint their
	// per-dial exec JWT through the SEPARATE exec signing key (ADR-0013 key
	// separation — never the Storage-JWT keyring). When -exec-signing-key is unset
	// execSigner is nil, so both stay nil: the Destroy nudge is a clean no-op and the
	// gateway exec verb fail-closes. The execDriverAdapter bridges the two decoupled
	// request/result shapes so neither the lifecycle nor the guestexec package
	// imports the other.
	var (
		controlDialer lifecycle.ControlDialer
		execDriver    lifecycle.ExecDriver
	)
	if execSigner != nil {
		controlDialer = controlrpc.NewDialer(execSigner, 0)
		execDriver = execDriverAdapter{driver: guestexec.NewDriver(execSigner)}
	}

	// Parse the comma-separated body-image override allow-list into exact-match
	// entries; blank fields (a trailing comma, whitespace) are dropped. The Manager
	// adds the default implicitly, so an empty list is default-only (deny-by-default).
	var allowedImages []string
	for _, img := range strings.Split(cfg.guestImageAllow, ",") {
		if trimmed := strings.TrimSpace(img); trimmed != "" {
			allowedImages = append(allowedImages, trimmed)
		}
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

		DefaultImage:  cfg.guestImage,
		AllowedImages: allowedImages,

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
		ExecDriver:    execDriver,
		ExecVerifyKey: execVerifyKeyOf(execSigner),
		Metrics:       collector,
	})
	eng := killswitch.NewEngine(store, custodian, provider, clk, sink)
	return mgr, eng, custodian, collector, sink
}

// execVerifyKeyOf returns the exec signer's public verify key, or nil when no exec
// signer is configured. The Manager stages this deployment-fixed key as the guest's
// --auth-public-key verify file; a nil key means the exec channel is disabled and a
// scoped create stages no verify key (the create still boots for the storage leg).
func execVerifyKeyOf(s *cred.ExecSigner) ed25519.PublicKey {
	if s == nil {
		return nil
	}
	return s.VerifyKey()
}

// execDriverAdapter bridges the guestexec.Driver to the lifecycle.ExecDriver seam.
// The two packages define their own request/result shapes (identical fields) so
// neither imports the other; this adapter — the one place that knows both — maps
// between them at the composition root.
type execDriverAdapter struct {
	driver *guestexec.Driver
}

func (a execDriverAdapter) Exec(ctx context.Context, sockDir, containerName string, req lifecycle.ExecRequest) (lifecycle.ExecResult, error) {
	res, err := a.driver.Exec(ctx, sockDir, containerName, guestexec.Request{
		Argv:     req.Argv,
		Env:      req.Env,
		Cwd:      req.Cwd,
		Stdin:    req.Stdin,
		TimeoutS: req.TimeoutS,
	})
	if err != nil {
		return lifecycle.ExecResult{}, err
	}
	return lifecycle.ExecResult{
		ExitCode:        res.ExitCode,
		Stdout:          res.Stdout,
		Stderr:          res.Stderr,
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
	}, nil
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
		// drain below waits for them after closeBoth. Tell systemd the graceful stop
		// has begun BEFORE the listeners finish draining — exactly once, and only on a
		// host-initiated SIGINT/SIGTERM, never on the serve-error arm below (a crash is
		// not a graceful stop). A no-op when not run under systemd.
		notifyStopping()
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

// renderJWKSArtifact emits the static JWKS document the deploy layer serves at the
// egress edge's remote_jwks URI (ADR-0019 §35), so the edge can validate the weak
// Storage-JWT via stock Envoy jwt_authn remote_jwks. It is the thin WHEN/WHETHER
// wiring around jwks.WriteArtifact, which owns the serialization and the atomic
// temp+fsync+rename write:
//
//   - -jwks-path UNSET: a clean no-op (nil). The minimal shelf may run without a
//     signer/path, so the unset case writes nothing and never fails closed.
//   - -jwks-path SET: render the artifact from the signer's LIVE PublicKeys() (the
//     active key plus, during a rotation overlap, the just-superseded key) and
//     write it atomically. An empty key set is a FAIL-CLOSED boot abort — never a
//     silently-written empty Set — surfaced as a typed error so
//     errors.Is(err, jwks.ErrEmptyKeySet) holds at the boot seam.
//
// It adds NO network surface: it hands signer.PublicKeys() to internal/jwks and
// lets that package own the bytes; cmd never touches JWK fields directly. v1 has no
// live rotation hook (cred rotates only via an operator/boot-driven Rotate the
// daemon does not call at runtime), so the render happens once at boot from the
// live PublicKeys(); a future live-rotation seam re-invokes WriteArtifact to
// re-render the served document atomically.
func renderJWKSArtifact(cfg config, signer *cred.Signer) error {
	if cfg.jwksPath == "" {
		return nil
	}
	var pub []cred.PublicKey
	if signer != nil {
		pub = signer.PublicKeys()
	}
	if err := jwks.WriteArtifact(cfg.jwksPath, pub); err != nil {
		return fmt.Errorf("boot: render jwks artifact: %w", err)
	}
	return nil
}

// buildMCPKeyEngine constructs the MCP API key Engine for boot-time composition.
// It selects the RecordStore backend by the -state-dsn flag (the same idiom as
// openStore: Postgres when non-empty, in-memory when empty), constructs a Minter
// from crypto/rand, and wires a re-render closure that (a) reads the live active
// record set from the store, (b) calls mcpkeyset.WriteKeySet when -mcp-keyset-path
// is set, and (c) when -mcp-key-file is set, rewrites the minimal-shelf entries
// file atomically. On boot, when -mcp-key-file is set and the file exists, it is
// LOADED fail-closed: a file with permissions looser than 0600 aborts boot BEFORE
// any listener binds (mirroring the kill-switch-first / signer fail-closed boot
// discipline). The loaded records seed the in-memory store so the in-process
// set survives a daemon restart when using the minimal shelf. The Engine is handed
// to the operator adapter ALONE (never the gateway adapter) — the caller ensures
// that by assigning it to operator.Deps.MCPKeyEngine only.
//
// The sink is the SAME audit.AuditSink chain compose() wired into the Manager and
// killswitch Engine (the same chain-linked spine for all operator ops, one durable
// writer). compose() exposes the constructed chain sink for exactly this reuse.
func buildMCPKeyEngine(ctx context.Context, cfg config, clk state.Clock, sink audit.AuditSink) (*mcpkey.Engine, error) {
	// Backend select: mirrors -state-dsn empty ⇒ in-memory (the minimal shelf
	// default, identical to openStore). The file-vs-DB choice stays here in the
	// daemon; it must NOT leak into the handler logic.
	var recordStore mcpkey.RecordStore
	if cfg.stateDSN == "" {
		// Minimal shelf: in-memory store. State is lost on restart; the optional
		// -mcp-key-file re-seeds it on the next boot.
		recordStore = mcpkey.NewInMemRecordStore()
	} else {
		// Full shelf: Postgres store. The DSN is the same one openStore uses for
		// the session state; we open a separate pool so the mcpkey schema is
		// migrated independently without touching the session store's pool.
		var err error
		recordStore, err = mcpkeypostgres.Open(ctx, cfg.stateDSN)
		if err != nil {
			return nil, fmt.Errorf("open mcp-key postgres store: %w", err)
		}
	}

	// If -mcp-key-file is set and the file already exists on disk, load it into
	// the in-memory store FAIL-CLOSED (before any listener binds). A file with
	// permissions looser than 0600 aborts boot: a world- or group-readable
	// hashed-entries file is a store-disclosure surface even though it holds
	// only hashes (mirroring the kill-switch-first boot discipline).
	if cfg.mcpKeyFile != "" {
		records, err := mcpkeyset.LoadEntriesFile(cfg.mcpKeyFile)
		if err != nil {
			// os.ErrNotExist: no prior entries file — clean start, not an error.
			if !errors.Is(err, os.ErrNotExist) {
				// Any other error — including ErrLoosePermissions — is fail-closed.
				return nil, fmt.Errorf("load mcp-key entries file %q: %w", cfg.mcpKeyFile, err)
			}
			// File does not exist yet: start with an empty in-memory store.
		} else {
			// Seed the in-memory store from the loaded records so the in-process
			// set reflects the on-disk minimal-shelf state after a daemon restart.
			for _, rec := range records {
				if err := recordStore.Put(ctx, rec); err != nil {
					return nil, fmt.Errorf("seed mcp-key store from entries file: %w", err)
				}
			}
		}
	}

	// The artifact re-render closure is called by the Engine on every successful
	// Create/Revoke. It delegates to renderMCPKeyArtifacts (extracted so the
	// last-key-revoke deny-all path is unit-testable — a closure hidden in this
	// factory could not be driven directly).
	minter := mcpkey.NewMinter()
	rerender := func(rerenderCtx context.Context) (mcpkey.RenderOutcome, error) {
		return renderMCPKeyArtifacts(rerenderCtx, cfg, recordStore, clk.Now())
	}
	return mcpkey.NewEngine(minter, recordStore, rerender, clk, sink), nil
}

// renderMCPKeyArtifacts writes the minimal-shelf hashed-entries file and the
// Control→gateway hashed-key-set artifact from the store's live record set. It is
// the daemon's re-render step, run by the Engine after every successful
// Create/Revoke, and is a named function (not an inline closure) so its two failure
// and boundary paths are directly testable.
//
// ORDER — entries FIRST, keyset second. The entries file is the durable at-rest
// record set that re-seeds the store on a restart; writing it first means a restart
// always reflects the latest mutation (a revoked key stays revoked), even if the
// keyset write below is skipped or fails. The prior order (keyset first, return on
// its error) left the entries file stale when a last-key revoke made WriteKeySet
// refuse, silently resurrecting the revoked key on the next boot.
//
// EMPTY ACTIVE SET is NOT an error. When a revoke removes the last active key,
// WriteKeySet returns ErrEmptyKeySet (the frozen A2 schema forbids an empty active
// set). That is the expected terminal state, so this function does not propagate it
// as a fault: it logs the deny-all-pending warning and returns
// RenderOutcome{DenyAllPending: true}, nil. The stale boot-set artifact is left in
// place (removing it would not converge a live gateway, which keeps its last-good
// set on a config-refresh miss); closing the live fail-open needs the canon
// deny-all-artifact contract, tracked as open-computer-use#332.
func renderMCPKeyArtifacts(ctx context.Context, cfg config, store mcpkey.RecordStore, now time.Time) (mcpkey.RenderOutcome, error) {
	// Entries file FIRST: the durable at-rest set (active + revoked) that re-seeds
	// the store on a restart, so a restart never resurrects a just-revoked key.
	if cfg.mcpKeyFile != "" {
		all, err := store.List(ctx)
		if err != nil {
			return mcpkey.RenderOutcome{}, fmt.Errorf("mcp-key entries rerender: enumerate: %w", err)
		}
		if err := mcpkeyset.WriteEntriesFile(cfg.mcpKeyFile, all); err != nil {
			return mcpkey.RenderOutcome{}, fmt.Errorf("mcp-key entries rerender: write: %w", err)
		}
	}

	if cfg.mcpKeysetPath != "" {
		// Active subset only (revoked/expired omitted — fail-closed).
		active, err := store.ActiveRecords(ctx, now)
		if err != nil {
			return mcpkey.RenderOutcome{}, fmt.Errorf("mcp-keyset rerender: enumerate active: %w", err)
		}
		if err := mcpkeyset.WriteKeySet(cfg.mcpKeysetPath, active, now); err != nil {
			if errors.Is(err, mcpkeyset.ErrEmptyKeySet) {
				// Terminal, expected state after revoking the last active key: the
				// schema cannot publish an empty set. NOT a fault — the revoke
				// succeeded. Warn (the live gateway does not yet converge to
				// deny-all; open-computer-use#332) and report DenyAllPending.
				fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: last active mcp-key revoked; the boot-set has no active keys to publish. "+
					"The revoke is durable (audit + store), but a live gateway keeps its last-good key set on a config-refresh miss, so it may keep accepting the revoked key until it restarts. "+
					"Converging the live gateway to deny-all needs the config-plane deny-all-artifact contract (open-computer-use#332).")
				return mcpkey.RenderOutcome{DenyAllPending: true}, nil
			}
			return mcpkey.RenderOutcome{}, fmt.Errorf("mcp-keyset rerender: write keyset: %w", err)
		}
	}
	return mcpkey.RenderOutcome{}, nil
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

// auditChainSource is the per-source spine name Control emits under (ADR-0009: Control
// is one source on the host audit fan-in).
const auditChainSource = "control"

// buildResumedChainSink constructs the OCSF chain sink over writer, RESUMED from the
// existing spine at path so a daemon restart continues the same per-source sequence
// and prior-hash link instead of re-anchoring at genesis (which would break the
// tamper-evidence chain across boots). It is fail-closed at boot:
//
//   - The non-durable opt-out (=none/=null, so path is not a real file) has no prior
//     spine to read, so it starts fresh at genesis — nothing to resume.
//   - A real file is read for its tip. A valid tail resumes the spine. A decoupled tail
//     (torn last write, truncation, tamper) records an EXPLICIT chain-break marker and
//     then continues — but if that marker cannot be durably written, the boot ABORTS:
//     continuing without recording the discontinuity would be the silent break the
//     whole design forbids.
//   - Before returning, the existing file is verified end-to-end (ValidateChain). A
//     file that already fails the chain aborts the boot rather than appending onto a
//     spine known to be broken.
func buildResumedChainSink(ctx context.Context, clk state.Clock, writer ocsf.EventWriter, path string) (*ocsf.ChainSink, error) {
	// The non-durable opt-out has no on-disk spine: start fresh at genesis.
	if auditSinkNone[strings.ToLower(path)] {
		return ocsf.NewChainSink(clk, writer, auditChainSource), nil
	}

	// Verify the existing spine end-to-end before appending to it: a file that already
	// fails the chain must not have new events appended onto a broken tail.
	if err := verifyAuditChainFile(path); err != nil {
		return nil, err
	}

	tip, err := ocsf.ReadTip(path)
	if errors.Is(err, ocsf.ErrTipDecoupled) {
		// The tail could not be read as a valid tip. Record the discontinuity as an
		// explicit chain-break marker, then continue on the new spine. The marker is
		// written through a fresh genesis-anchored sink; if the write FAILS, the boot
		// aborts — a boot that cannot durably record the break would leave a silent one.
		genesisSink := ocsf.NewChainSink(clk, writer, auditChainSource)
		if berr := genesisSink.EmitChainBreak(ctx, ocsf.ChainBreakUnreadable); berr != nil {
			return nil, fmt.Errorf("record audit chain-break at %q: %w", path, berr)
		}
		fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: the audit file tail at "+path+" was not a valid chain tip (a torn last write, truncation, or tamper). A chain-break marker was recorded; the spine continues from it. Investigate the discontinuity.")
		return genesisSink, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read audit tip at %q: %w", path, err)
	}
	return ocsf.ResumeChainSink(clk, writer, auditChainSource, tip), nil
}

// verifyAuditChainFile reads every envelope in the audit file at path and runs
// ValidateChain over the whole spine, so a boot never appends onto a file whose
// existing chain is already broken (a tamper or a corruption detected post-hoc). An
// absent or empty file is a valid (empty) chain. This is the shipped, non-test caller
// of ValidateChain — the tamper-evidence checker actually runs at boot.
//
// Cost note: it reads the WHOLE file at boot. That is acceptable in v1 because the
// files are young (the daily Merkle-head submission and cold-tier rotation that bound
// the hot file are downstream seams not yet wired), so the hot spine stays small. A
// checkpoint-and-verify-suffix optimization is a later concern tracked with the
// external-anchor follow-up.
func verifyAuditChainFile(path string) error {
	envs, err := ocsf.ReadChainFile(path)
	if err != nil {
		return fmt.Errorf("read audit chain at %q: %w", path, err)
	}
	if err := ocsf.ValidateChain(envs); err != nil {
		return fmt.Errorf("audit chain at %q is invalid (tamper evidence): %w", path, err)
	}
	return nil
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

// buildGatewayTLSConfig builds the gateway mTLS server config from the
// -gateway-tls-* flags, or returns (nil, nil) when they are unset (the stubbed
// plain-TCP posture). validate() already enforced all-or-none, so an unset cert
// means all three are unset. It is FAIL-CLOSED: an unreadable cert/key pair or an
// unparseable client-CA aborts boot before any listener binds. The config REQUIRES
// AND VERIFIES a client cert against the client-CA at a TLS 1.3 floor, so a
// connection's verified SAN is a real host-attested identity.
func buildGatewayTLSConfig(cfg config) (*tls.Config, error) {
	if cfg.gatewayTLSCert == "" {
		return nil, nil
	}
	serverCert, err := tls.LoadX509KeyPair(cfg.gatewayTLSCert, cfg.gatewayTLSKey)
	if err != nil {
		return nil, fmt.Errorf("gateway tls key pair: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.gatewayClientCA)
	if err != nil {
		return nil, fmt.Errorf("gateway client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("gateway client CA %q: no PEM certificate parsed", cfg.gatewayClientCA)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
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
// revokeOutcomeAuditor adapts the durable audit sink to the docker.RevokeAuditor
// seam: it records the teardown finalizer step-1 revoke result as an evidence
// detail on a destroy record. The revoke outcome is not a distinct privileged
// action — it is the outcome of a destroy whose ActionDestroy record was already
// emitted fail-closed on the create/destroy path — so this emits a follow-on
// destroy record carrying the outcome in metadata.unmapped.revoke_outcome, never a
// new Action value. The record Key is the bind's host-derived SessionName — the
// SAME value the primary ActionDestroy record keys on (lifecycle builds both the
// destroy key and the teardown Sandbox from row.Key), so the evidence and its
// destroy event join on one CorrelationUID. The FilesystemID (the mount scope the
// revoke targeted) stays in the warning text and the revoke context; it is never a
// body hint.
//
// A none_bound outcome on a live destroy is an anomaly (a session whose mint was
// never bound), and this records it AS none_bound — it never skips the emit on
// none_bound, because the whole point of the evidence is that the anomaly is
// visible in the tamper-evident spine. An Emit failure here does NOT fail the
// destroy: the ActionDestroy that authorises the teardown was already recorded
// fail-closed upstream, and step-1 is idempotent; a lost evidence detail is logged,
// not escalated to a teardown abort (which would strand the container).
type revokeOutcomeAuditor struct {
	sink audit.AuditSink
}

func (a revokeOutcomeAuditor) RecordRevokeOutcome(ctx context.Context, sess runtime.EgressBinding, outcome runtime.RevokeOutcome) {
	rec := audit.Record{
		Action:        audit.ActionDestroy,
		Key:           string(sess.Name),
		RevokeOutcome: outcome.String(),
	}
	if err := a.sink.Emit(ctx, rec); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-controld: WARNING: could not record the teardown revoke outcome "+outcome.String()+" for session "+string(sess.Name)+" (mount scope "+sess.FilesystemID+") as destroy evidence: "+err.Error()+" (the destroy was already authorised fail-closed upstream and step-1 is idempotent; only this evidence detail is lost)")
	}
}

func providerOf(name string, tier runtime.RuntimeTier, revoker docker.Revoker, stagerBase, egressNetwork, edgeHost string, sink audit.AuditSink) (runtime.RuntimeProvider, error) {
	switch name {
	case "docker":
		// The shared Revoker is the below-seam finalizer step-1 (revoke session JWT)
		// target; the same instance the Signer records mints against. StagerBase is the
		// finalizer step-3 (handoff-root scrub) base — the SAME path the handoff Stager
		// writes under, so teardown reclaims the host-owned credential tree. The
		// RevokeAuditor records the step-1 revoke outcome as destroy evidence; it is
		// built HERE from the durable sink (never passed pre-wrapped) so the call site
		// cannot hand the provider a nil auditor — the sink is fail-closed at boot, so
		// it is always live by the time this runs. EgressNetwork/EdgeHost are the
		// deployment-fixed storage-egress wiring: the network a storage-scoped guest
		// joins to reach the edge, and the static `edge` IP a gVisor guest resolves it
		// by (embedded DNS is unreachable from the sentry). Both empty on a non-storage
		// or minimal-shelf deployment — every session then stays on its per-session
		// Internal deny-all bridge.
		p, err := docker.NewDockerProvider(tier, docker.Deps{Revoker: revoker, StagerBase: stagerBase, RevokeAuditor: revokeOutcomeAuditor{sink: sink}, EgressNetwork: egressNetwork, EdgeHost: edgeHost})
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
