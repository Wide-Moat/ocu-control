// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package lifecycle is the heart of the control plane: the ordered, fail-closed
// session create pipeline with a LIFO unwind stack, the audience-scoped destroy
// path, and the boot orphan-sweep reconciler. It owns the create ORDER as DATA (a
// []stage slice) so the no-orphan property — a fault at stage N leaves every
// compensator for stages 1..N-1 run exactly once in reverse, and no residual row,
// counter, container, or sockdir — is a per-stage assertable fact rather than
// control flow buried in one function.
//
// The Manager routes EVERY registry mutation through registry.Custodian (the sole
// Store-mutator caller, requirement 4); it never calls the four Store reservation
// mutators directly. It is a PURE domain: no net/http, no socket, no SDK, so the
// three NFR-mandated property tests (admission totality, quota no-overcommit,
// create no-orphan) run as plain function calls against an in-memory Store, a fake
// Provider, and the audit RecordingFake with no transport bound.
//
// The create path is the canon fail-closed order encoded once as m.stages:
// resolveIdentity → admit → quotaCharge → reserve → stageHandoff → materialize →
// commit → bindContainerName. Each stage, on success, pushes a compensator onto a
// LIFO stack; on the FIRST stage failure the Manager runs every pushed compensator
// in reverse under context.WithoutCancel with a per-step bounded timeout, so a
// client disconnect mid-create cannot abort rollback and strand an orphan. The
// admit and quota stages run BEFORE any durable host state; the commit stage is the
// single privileged create checkpoint that emits an audit record before ack and
// denies the create fail-closed if the audit write fails.
//
// profile and tier are DEPLOYMENT-fixed (never per-request): the Manager holds both
// as fixed fields and CreateInput carries neither, which is the structural guarantee
// that a request body cannot steer the admission matrix.
package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/mountcfg"
	"github.com/Wide-Moat/ocu-control/internal/provisioning"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// unwindStepTimeout bounds each compensator and each teardown step run under the
// detached unwind context, so a single slow Store or Provider call cannot wedge
// rollback indefinitely. It mirrors the bounded per-step discipline the runtime
// finalizer and the quota refund already use.
const unwindStepTimeout = 5 * time.Second

// destroyGrace is the SIGTERM-then-kill drain window (whole seconds) the destroy
// path gives a session before the host kills it. It is a small fixed drain; a
// kill-switch force-kill uses ForceKill (no drain) instead.
const destroyGrace runtime.Duration = 5

// ErrUnattested is the hard reject at the create/destroy path when the
// host-derived caller identity is empty. The ingress resolver should already have
// refused an unattested connection with ingress.ErrUnattested before the Manager
// is reached; this is the Manager's own fail-closed backstop so an empty Identity
// can never seed a Key or touch host state.
var ErrUnattested = errors.New("lifecycle: caller identity unattested, refused (fail-closed)")

// ErrInvalidArgument marks a create refused because the REQUEST itself (body +
// deployment-wide config, never per-tenant or store state) does not resolve to a
// runnable session. The gateway maps it to HTTP 400: it is the same
// request-derived, client-error class as the ingress toRequest() decode refusal,
// evaluated after image resolution. It is SAFE to surface (unlike the 409/404
// collapse that hides cross-tenant existence) precisely because it consults no
// tenant state — so it can never be an existence oracle. Contract: the Manager
// wraps ONLY request-derivable failures in this sentinel; an error that touched
// the store or another tenant's row must NEVER be wrapped here.
var ErrInvalidArgument = errors.New("lifecycle: invalid create argument")

// CreateInput is what an ingress hands the Manager. It carries NO trusted identity:
// the authority is the host-derived AuthenticatedCaller the ingress resolved, and
// SessionHint is explicitly a HINT — it seeds the human-readable host-minted handle,
// never the namespace or the derived Key (NFR-SEC-43).
type CreateInput struct {
	// Caller is the host-derived authority the ingress resolved from peer creds
	// (operator) or the verified cert SAN (gateway). It is the ONLY identity the
	// Manager acts on.
	Caller ingress.AuthenticatedCaller
	// SessionHint is the body-supplied id. It is a HINT used only to seed the
	// host-minted handle for human correlation; it never becomes the Key.
	SessionHint string
	// Image is the sandbox container image reference the provider runs.
	Image string
	// Mount is the per-session storage mount intent. Its AuthToken is a later-phase
	// placeholder on this path.
	Mounts []runtime.MountIntent
	// Egress is the per-session egress trust-edge policy.
	Egress runtime.EgressPolicy
	// Resources are the hard caps the provider stamps onto the runtime.
	Resources runtime.ResourceCaps
}

// ManagerDeps are the collaborators the stages call. Profile and Tier are
// deployment-fixed (never per-request) and bound once at construction.
type ManagerDeps struct {
	// Custodian is the sole Store-mutator caller every registry mutation routes
	// through (requirement 4).
	Custodian *registry.Custodian
	// Provider materializes and tears down the substrate sandbox.
	Provider runtime.RuntimeProvider
	// Clock is the injected time seam; the Manager never reads the wall clock
	// directly.
	Clock state.Clock
	// Quota is the create-time quota gate (charge-rate then concurrent, atomic).
	Quota *quota.Gate
	// Handoff stages the host-side handoff material under a per-session root.
	Handoff handoff.Stager
	// Audit is the fail-closed audit sink the commit and destroy checkpoints emit
	// through before acknowledging.
	Audit audit.AuditSink
	// Profile is the deployment-declared workload trust profile (fixed).
	Profile admission.WorkloadProfile
	// Tier is the deployment-wide isolation tier (fixed).
	Tier runtime.RuntimeTier
	// DefaultImage is the deployment-declared guest image a create runs when the
	// body names none — the inject-at-materialize default of the ADR-0020
	// provisioning ladder (image is deployment configuration, never caller data).
	// The body image, when set, is an override. Create resolves the effective image
	// from this default BEFORE admission, so admission validates the resolved value
	// and an empty result is refused as a clean invalid-argument, never a cryptic
	// rolled-back materialize. Empty here is a valid minimal-shelf posture: a create
	// that also names no body image is then refused (fail-closed, no silent "").
	DefaultImage string
	// AllowedImages is the deployment-declared allow-list of guest images a create
	// BODY may override the default with (ADR-0020 BYO rung). Membership is EXACT
	// string match — no glob or prefix (image refs carry tags/digests a prefix rule
	// would foot-gun). The DefaultImage is IMPLICITLY allowed (the operator already
	// trusted it), so a body naming the default is always equivalent to an empty
	// body. Empty here is deny-by-default: only the default is allowed, so a body
	// override is refused unless the operator explicitly lists it. The solo
	// one-command path names no body image, so it never touches this gate.
	AllowedImages []string

	// Signer is the SOLE Storage-JWT custodian the mint stage calls. It mints the
	// weak, edge-only Storage-JWT and records its jti against the host-derived
	// session key on the shared Revoker, so the below-seam finalizer can revoke it.
	// nil disables the mint+render stages (the Phase-3 minimal shelf), so a
	// deployment without storage provisioning still runs the base pipeline.
	Signer *cred.Signer
	// Push delivers the rendered mount-config into the host-owned handoff bind
	// BEFORE the in-guest mount client boots, and triggers the scrub on unwind. nil
	// disables the render+push stage alongside a nil Signer.
	Push provisioning.Pusher
	// ServiceURL is the deployment-fixed filestore service_url rendered into every
	// mount-config (the frozen ^https:// top-level field).
	ServiceURL string
	// CACertPEM is the deployment-fixed CA certificate rendered into every
	// mount-config (the frozen ca_cert_pem top-level field).
	CACertPEM string
	// MountDefaults are the deployment-fixed, schema-validated per-mount knobs the
	// substrate-neutral MountIntent does not carry (VFS cache policy/cap, perm
	// bits). Host-chosen posture, never a request-body hint.
	MountDefaults mountcfg.MountDefaults
	// StorageScope is the deployment-fixed, host-derived scope the Storage-JWT is
	// minted under (workspace/org/downloadable). The mint INTENT is no longer taken
	// from here — it is derived per-session from the mount's read-only posture
	// (ADR-0029); StorageScope.Intent is retained for the no-signer minimal shelf and
	// as the provisional default. It is NEVER sourced from a request body (NFR-SEC-43).
	StorageScope StorageScope
	// GrantedIntents is the deployment -granted-intents ceiling: the set of intents
	// the deployment serves. It never grants — a per-mount-derived intent outside it
	// refuses the mint fail-closed (ADR-0029 §Decision). A zero IntentCeiling admits
	// nothing (every storage-scoped create then refuses), so the daemon wires
	// DefaultIntentCeiling on the minimal shelf; the flag only ever narrows it.
	GrantedIntents IntentCeiling

	// ControlDialer is the ADVISORY host-dialled control-RPC surface (ADR-0018). On
	// Destroy the Manager dials it BEFORE the host-driven finalizer to advance the
	// cooperative SIGTERM phase; the dial is best-effort and its result is swallowed
	// — the finalizer (NFR-SEC-65) is authoritative and never waits on the reply. A
	// nil ControlDialer (the Phase-3 minimal shelf, or a deployment without the
	// control-RPC wire) makes the dial a clean no-op.
	ControlDialer ControlDialer

	// ExecDriver is the guest exec-channel driver (ADR-0024) the gateway exec verb
	// routes through. A nil ExecDriver (a deployment without the exec channel, or
	// the minimal shelf) makes Exec a fail-closed refusal.
	ExecDriver ExecDriver

	// ExecVerifyKey is the DEPLOYMENT-FIXED raw 32-byte Ed25519 PUBLIC key the guest
	// verifies host-signed exec/control frames against — the public half of the
	// separate exec signing key (ADR-0013). It is host-derived deployment config,
	// never a request-body hint (NFR-SEC-43: the verify key decides who counts as
	// the host, so the caller cannot supply it). The Manager stages it as the
	// guest's --auth-public-key file on every create. A nil key means the exec
	// channel is disabled; a scoped create still boots for the storage leg with no
	// verify key staged.
	ExecVerifyKey ed25519.PublicKey

	// Metrics is the OBSERVABILITY recorder the Manager increments on a successful
	// create/destroy and observes the reserved->active start duration into for the
	// admin /metrics surface. It is purely observational and NON-FATAL: a nil
	// recorder disables metric recording, and no recording can fail a create or a
	// destroy (the calls are made after the action has already succeeded). It carries
	// no authority and sees no credential.
	Metrics Recorder

	// Events is the DESIGN-FENCED live-view fan-out the Manager publishes lifecycle
	// transitions to for the admin console's eventual SSE surface (ADR-0022). It is a
	// SEAM: nil leaves publishing a clean no-op (the console polls the GET endpoints),
	// and the real broadcast hub is wired when the SSE event schema freezes (Open
	// Question #2). Publishing is best-effort and NON-FATAL — it never blocks or fails
	// a create/destroy.
	Events EventPublisher
}

// Recorder is the NARROW observability port the Manager records lifecycle metrics
// through. It is satisfied by *metrics.Collector but names only the three events
// the lifecycle produces, so the Manager depends on the events, not the exporter.
// Every method is non-fatal and observational — a nil Recorder is a clean no-op via
// the Manager's guarded calls.
type Recorder interface {
	// IncCreate records a successful session create.
	IncCreate()
	// IncDestroy records a successful session destroy.
	IncDestroy()
	// ObserveStart records one reserved->active start duration.
	ObserveStart(d time.Duration)
	// IncQuotaRefundFailed records one quota-refund compensator failure on the create
	// unwind — a swallowed refund that leaves the concurrency cell drifted until the
	// boot cell-reconcile heals it.
	IncQuotaRefundFailed()
}

// ControlDialer is the NARROW seam the Destroy path reaches the advisory
// control-RPC Shutdown through. It is satisfied by *controlrpc.Dialer but names
// only Shutdown, so the lifecycle Manager depends on the one advisory verb, not
// the whole dialer (and never on the exec-JWT minter behind it). The dial is
// best-effort: every Shutdown error is non-authoritative for teardown.
type ControlDialer interface {
	Shutdown(ctx context.Context, sockDir, containerName string) error
}

// StorageScope is the deployment-fixed, host-derived scope every Storage-JWT mint
// carries. Workspace/Org/Intent/Downloadable are provisional alongside iss/aud
// and are bound once at construction from deployment config plus the host-derived
// session identity — never from the request body (NFR-SEC-43).
type StorageScope struct {
	// Workspace and Org are the deployment-fixed scope axes the egress edge keys
	// on. Provisional, PIN-PENDING the Phase-7 contract pin.
	Workspace string
	Org       string
	// Scope is the AuthorizationMetadata scope axis; empty means the default
	// (above-public) scope, under which Downloadable must stay false.
	Scope string
	// Intent is the access axis (read|write|preview). The mint refuses an invalid
	// intent fail-closed.
	Intent cred.Intent
	// Downloadable is the third access axis; it defaults false and the mint refuses
	// a downloadable-true with an empty Scope.
	Downloadable bool
}

// Manager owns the create pipeline, the unwind stack, the destroy path, and the
// boot reconciler. It drives Materialize/Teardown and routes ALL registry mutation
// through the Custodian (requirement 4: no direct Store mutator call here).
type Manager struct {
	reg      *registry.Custodian
	provider runtime.RuntimeProvider
	clk      state.Clock
	quota    *quota.Gate
	handoff  handoff.Stager
	audit    audit.AuditSink
	stages   []stage // the canon fail-closed ORDER, encoded once as data
	profile  admission.WorkloadProfile
	tier     runtime.RuntimeTier

	// defaultImage is the deployment-declared guest image a create falls back to
	// when the body names none (ADR-0020 inject-at-materialize). Resolved in Create
	// before admission; empty + no body image is a fail-closed refusal.
	defaultImage string
	// allowedImages is the exact-match allow-list a create BODY may override the
	// default with (deny-by-default: a body image not here AND not equal to
	// defaultImage is refused). Built as a set at construction so the Create check is
	// O(1); the defaultImage is added implicitly.
	allowedImages map[string]bool

	// Storage-JWT custody + mount-config provisioning (Phase 4). signer/push are nil
	// on the Phase-3 minimal shelf, which the mint+render stages skip cleanly.
	signer         *cred.Signer
	push           provisioning.Pusher
	serviceURL     string
	caCertPEM      string
	mountDefaults  mountcfg.MountDefaults
	storageScope   StorageScope
	grantedIntents IntentCeiling

	// controlDialer is the advisory host-dialled control-RPC surface Destroy nudges
	// before the authoritative finalizer. nil is a clean no-op.
	controlDialer ControlDialer

	// execDriver is the guest exec-channel driver the gateway exec verb routes
	// through. nil makes Exec a fail-closed refusal.
	execDriver ExecDriver

	// execVerifyKey is the deployment-fixed guest verify key staged on every create
	// (host-derived, never a body hint). nil disables the exec channel.
	execVerifyKey ed25519.PublicKey

	// metrics is the non-fatal observability recorder. nil is a clean no-op (every
	// call site guards on it), so the base pipeline runs without an exporter wired.
	metrics Recorder

	// events is the design-fenced live-view fan-out. nil is a clean no-op (the guarded
	// publishEvent), so the base pipeline runs without a fan-out hub wired.
	events EventPublisher
}

// NewManager constructs a Manager from its deps and binds the canon create order
// into m.stages once. The stage slice IS the create order — adding a stage is a
// one-line edit and the no-orphan property test re-derives its fault points from
// the slice length, so the order can never silently drift from what is tested.
func NewManager(deps ManagerDeps) *Manager {
	m := &Manager{
		reg:      deps.Custodian,
		provider: deps.Provider,
		clk:      deps.Clock,
		quota:    deps.Quota,
		handoff:  deps.Handoff,
		audit:    deps.Audit,
		profile:  deps.Profile,
		tier:     deps.Tier,

		defaultImage: deps.DefaultImage,

		signer:         deps.Signer,
		push:           deps.Push,
		serviceURL:     deps.ServiceURL,
		caCertPEM:      deps.CACertPEM,
		mountDefaults:  deps.MountDefaults,
		storageScope:   deps.StorageScope,
		grantedIntents: deps.GrantedIntents,
		controlDialer:  deps.ControlDialer,
		execDriver:     deps.ExecDriver,
		execVerifyKey:  deps.ExecVerifyKey,
		metrics:        deps.Metrics,
		events:         deps.Events,
	}
	// Build the body-image override allow-set: the explicitly listed images plus the
	// deployment default (implicitly allowed — the operator already trusted it by
	// setting -guest-image; requiring it to be re-listed would 400 a body that names
	// the same ref as the empty-body default). An empty list yields a set holding only
	// the default: deny-by-default for overrides.
	m.allowedImages = make(map[string]bool, len(deps.AllowedImages)+1)
	if deps.DefaultImage != "" {
		m.allowedImages[deps.DefaultImage] = true
	}
	for _, img := range deps.AllowedImages {
		if img != "" {
			m.allowedImages[img] = true
		}
	}
	// The mint + render/push stages slot AFTER stageHandoff and BEFORE
	// stageMaterialize: the host-owned bind must carry the mount-config before
	// stageMaterialize starts the container, so the in-guest mount client never
	// boots without it. The no-orphan property test re-derives its fault points
	// from this slice length, so the new compensators are exercised automatically.
	m.stages = []stage{
		{name: "resolveIdentity", run: stageResolveIdentity},
		{name: "admit", run: stageAdmit, emitsOwnRejection: true},
		{name: "quotaCharge", run: stageQuotaCharge, emitsOwnRejection: true},
		{name: "reserve", run: stageReserve, emitsOwnRejection: true},
		{name: "stageHandoff", run: stageStageHandoff},
		{name: "mintStorageJWT", run: stageMintStorageJWT},
		{name: "renderPushMount", run: stageRenderPushMount},
		{name: "materialize", run: stageMaterialize},
		{name: "commit", run: stageCommit},
		{name: "bindContainerName", run: stageBind},
	}
	return m
}

// stage is one named, testable pipeline step. run does the work and, on success,
// returns a compensator the Manager pushes onto the LIFO unwind stack; on failure
// it returns the typed stage error and NO compensator (a failing stage cleans up
// after itself before returning, so the unwind reverses only the stages that
// SUCCEEDED). The stage list IS the canon fail-closed order — order is data, not
// control flow.
type stage struct {
	name string
	run  func(ctx context.Context, m *Manager, st *createState) (compensator, error)
	// emitsOwnRejection marks a stage that ALREADY writes its own create-rejection
	// audit record on failure (the pre-side-effect deny stages: admit, quota,
	// reserve — each with its own specific cause). For those the runner does NOT emit
	// a second generic "stage-failed:<name>" record, so a deny keeps exactly one
	// record carrying its precise cause. A host-side stage (handoff/mint/render/
	// materialize/commit/bind) leaves this false, so the runner emits the rejection
	// record on its behalf — the observability the host-side stages previously lacked.
	emitsOwnRejection bool
}

// compensator is one entry on the LIFO unwind stack: the reverse of a successful
// stage (Release, Receipt.Apply, ForceKill, Unstage). It is idempotent and runs
// under the detached, per-step-bounded unwind context.
type compensator func(ctx context.Context) error

// createState threads values between stages. The key is host-derived
// (registry.Key, NOT the body hint) — a compile fact via the registry package.
type createState struct {
	in      CreateInput
	owner   state.Identity
	handle  string
	key     registry.Key
	row     state.SessionRow
	staged  handoff.Staged
	spec    runtime.SessionSpec
	sandbox runtime.Sandbox
	// reservedMark is the monotonic instant the reservation row was written, stamped
	// at stageReserve. stageCommit observes clk.Since(reservedMark) into the
	// reserved->active start-duration metric — a monotonic interval, so a wall-clock
	// setback between reserve and commit cannot skew the start histogram.
	reservedMark time.Time
	// storageTokens are the freshly minted weak Storage-JWTs the render stage carries
	// into the mount-config. It stays a secret cred.Token on the create state — it
	// never widens the frozen runtime.MountIntent.AuthToken string seam — and is
	// revealed only at the single mountcfg.Marshal boundary.
	storageTokens []cred.Token
	// pushed is the host-side handle to the pushed mount-config; its Scrub is the
	// render stage's compensator and (later) the finalizer's scrub-trigger.
	pushed provisioning.Pushed
}

// Create runs the ordered fail-closed pipeline (m.stages) with a LIFO unwind stack.
// On success it returns the host-assigned SessionRow (ACTIVE, ContainerName bound)
// and discards the unwind stack. On ANY stage failure it pops and runs every pushed
// compensator in reverse — under context.WithoutCancel with a per-step bounded
// timeout, so a client disconnect mid-create cannot abort rollback and strand an
// orphan — then returns the typed stage error, leaving no row, counter, container,
// or sockdir.
func (m *Manager) Create(ctx context.Context, in CreateInput) (state.SessionRow, error) {
	// Resolve the effective guest image BEFORE admission, so admission and every
	// later stage see the deployment-injected default, and a request that resolves
	// to no image is refused as a request-derived invalid argument (clean 400) here
	// — never as a cryptic rolled-back materialize below the runtime seam. The body
	// image (in.Image) is the override; the deployment default fills an empty body.
	// This is request-derived only (body + fixed config), so wrapping it in
	// ErrInvalidArgument leaks no tenant state.
	if in.Image == "" {
		in.Image = m.defaultImage
	}
	if in.Image == "" {
		return state.SessionRow{}, fmt.Errorf("%w: no guest image (body named none and no deployment default is configured)", ErrInvalidArgument)
	}
	// Gate the resolved image against the deployment allow-set (ADR-0020 BYO rung):
	// the default is implicitly a member (resolved above), so an empty body always
	// passes; a body override that is not listed is refused as a request-derived
	// invalid argument (clean 400) HERE, before admission — an untrusted MCP caller
	// cannot name an arbitrary image. Deny-by-default: an empty allow-list admits only
	// the default. This consults only the request image and fixed config, so wrapping
	// it in ErrInvalidArgument leaks no tenant state.
	if !m.allowedImages[in.Image] {
		return state.SessionRow{}, fmt.Errorf("%w: guest image %q is not in the deployment allow-list", ErrInvalidArgument, in.Image)
	}

	st := &createState{in: in}

	// Idempotent-create guard: a gateway that reuses a stable per-chat session hint
	// sends the SAME hint on every tool-call in an agent loop. Because the host handle
	// mintHandle produces is DETERMINISTIC in the hint and DeriveKey mixes the
	// host-attested owner in, the second create derives the SAME key as the live
	// session — so S4 Reserve would fail ErrReservationExists and the ingress would map
	// it to an opaque 409, breaking the multi-step chat. Instead, if the derived key
	// already names the caller's OWN, ACTIVE session, RESUME it: return the existing row
	// (the guest is already up) BEFORE the pipeline runs. The guard resolves identity
	// first (the same read-only S1 the loop re-runs — a pure re-derivation, no side
	// effect) so it addresses the row by the host-derived key, never a body hint.
	if resumed, row, err := m.tryResume(ctx, st); err != nil {
		return state.SessionRow{}, err
	} else if resumed {
		return row, nil
	}

	// The unwind stack grows as each stage succeeds; on a failure it is replayed in
	// reverse. A nil compensator (read-only stage) is never pushed.
	compensators := make([]compensator, 0, len(m.stages))

	for _, s := range m.stages {
		comp, err := s.run(ctx, m, st)
		if err != nil {
			// A host-side stage (one that does not emit its own rejection) failing after
			// durable state previously recorded nothing — the refusal surfaced only as an
			// opaque 409. Emit the SAME ActionCreateRejected the deny stages emit, with the
			// failing stage in the Reason, so the audit trail names WHICH stage refused.
			// The deny stages (emitsOwnRejection) already recorded their own specific cause,
			// so the runner does not double-emit for them. resolveIdentity fails before an
			// owner exists, so the owner guard skips the emit (no actor to attribute it to);
			// its ErrUnattested is a pre-owner reject the ingress already refused upstream.
			if !s.emitsOwnRejection && st.owner.Caller != "" {
				// The emit is best-effort observability, NOT a second fail-closed gate: the
				// create already failed and is about to unwind. An emit failure must not
				// mask the real stage error the caller needs, so it is swallowed here (the
				// deny stages' emits ARE fail-closed because they are the record of record;
				// this is a supplementary trail for an already-failing host-side stage).
				_ = emitCreateRejected(ctx, m, st, "stage-failed:"+s.name)
			}
			m.unwind(ctx, compensators)
			return state.SessionRow{}, fmt.Errorf("lifecycle: create stage %q: %w", s.name, err)
		}
		if comp != nil {
			compensators = append(compensators, comp)
		}
	}
	// The create succeeded (every stage committed, no unwind). Record it for the
	// admin /metrics surface — purely observational, after the fact, never able to
	// affect the create outcome.
	if m.metrics != nil {
		m.metrics.IncCreate()
	}
	// Publish the live-view delta (the session reached ACTIVE) to the design-fenced
	// fan-out — non-fatal, nil-safe; the console renders it when SSE is wired, and
	// polls the GET endpoints until then.
	m.publishEvent(ctx, state.StateActive, st.row.Key)
	return st.row, nil
}

// tryResume implements the idempotent-create guard. It resolves the host-derived
// identity and key (the read-only S1 derivation) and looks the caller's OWN row up by
// that key. It returns (resumed=true, row, nil) ONLY when the key already names a
// live, caller-owned ACTIVE session — in which case the create RESUMES it: the
// existing row is returned and the whole S2..S10 pipeline is skipped, so the
// concurrency cell is NOT charged a second time (the live session already holds its
// slot — a clean skip, never a charge-then-refund). The resume is audited fail-closed
// (ActionCreateResume) BEFORE the row is returned, so an audit-write failure denies
// the resume exactly as a create-commit audit failure denies a create.
//
// It returns (false, _, nil) — fall through to the normal pipeline — in every case
// that is NOT an own-ACTIVE collision:
//   - no such row (LookupForCaller ErrNotOwned, which also collapses a FOREIGN owner's
//     row: DeriveKey mixed a different owner in, so a foreign caller derives a
//     DIFFERENT key and never lands on the victim's row — NFR-SEC-43, boundary #1);
//   - a RELEASED tombstone (the prior session ended; a fresh create is correct);
//   - a RESERVED row (a create is racing in-flight; resuming a not-yet-active row
//     would hand back an unbound session, so this falls through and S4 Reserve returns
//     the honest ErrReservationExists — boundary #2, ACTIVE-only).
//
// A lookup error other than a benign not-found is returned as a hard failure: the
// guard must not fall through to a create on an ambiguous store fault (that could
// double-provision), so it fails closed.
func (m *Manager) tryResume(ctx context.Context, st *createState) (bool, state.SessionRow, error) {
	// Resolve the host-derived owner and key via the same read-only S1 stage the loop
	// re-runs. A pure re-derivation with no side effect: it only fills st.owner/st.key.
	if _, err := stageResolveIdentity(ctx, m, st); err != nil {
		return false, state.SessionRow{}, fmt.Errorf("lifecycle: create resolve identity: %w", err)
	}

	row, err := m.reg.LookupForCaller(ctx, st.key, st.owner)
	if err != nil {
		if errors.Is(err, registry.ErrNotOwned) {
			// No caller-owned row at this key (absent, or a foreign owner's row collapsed
			// to not-found). Not a resume — run the normal create.
			return false, state.SessionRow{}, nil
		}
		// An ambiguous store fault: fail closed rather than risk a double-provision.
		return false, state.SessionRow{}, fmt.Errorf("lifecycle: create resume lookup: %w", err)
	}

	// Boundary #2: resume ONLY a live ACTIVE session. A RESERVED row (create racing) or
	// a RELEASED tombstone (prior session ended) falls through to the normal pipeline.
	if row.State != state.StateActive {
		return false, state.SessionRow{}, nil
	}

	// The key names the caller's OWN, ACTIVE session: RESUME it. Audit FIRST,
	// fail-closed — the trail must record the reuse as durable before the row is
	// acknowledged, exactly as create-commit audits before ack. The actor is the
	// host-attested owner (NFR-SEC-43); the correlation handle is the host-derived key.
	rec := audit.Record{
		Action:  audit.ActionCreateResume,
		Channel: st.in.Caller.Channel.String(),
		Key:     st.key.String(),
		Caller:  st.owner.Caller,
		Tenant:  st.owner.Tenant,
	}
	if err := m.audit.Emit(ctx, rec); err != nil {
		return false, state.SessionRow{}, fmt.Errorf("lifecycle: create resume audit: %w", err)
	}

	// Publish the live-view delta (the session is reused, still ACTIVE) to the
	// design-fenced fan-out — non-fatal, nil-safe, mirroring the create/destroy path.
	m.publishEvent(ctx, state.StateActive, row.Key)
	return true, row, nil
}

// unwind runs every pushed compensator in REVERSE (LIFO) under a context detached
// from the caller's cancellation (context.WithoutCancel) with a per-step bounded
// timeout, so a cancelled request context cannot abort rollback and strand an
// orphan. Each compensator is idempotent; a compensator error is recorded as the
// first error but does not stop the remaining ones from running — one wedged step
// must never strand a resource a later compensator would free.
func (m *Manager) unwind(ctx context.Context, compensators []compensator) {
	base := context.WithoutCancel(ctx)
	for i := len(compensators) - 1; i >= 0; i-- {
		comp := compensators[i]
		stepCtx, cancel := context.WithTimeout(base, unwindStepTimeout)
		// A compensator error is intentionally not surfaced over the original stage
		// error: the create already failed, the compensators are idempotent, and the
		// boot reconciler reclaims any residue a wedged step left. Run every remaining
		// compensator regardless.
		_ = comp(stepCtx)
		cancel()
	}
}

// handleVersion prefixes the host-minted handle so a future change to the handle
// scheme is distinguishable and a handle minted under an earlier scheme never
// collides with one minted under a later scheme.
const handleVersion = "ocu-h-v1"

// mintHandle produces the host-minted session handle the Key is derived from. The
// handle is DETERMINISTIC in the body SessionHint — within a caller's namespace a
// hint names exactly one session — so the create and a later Destroy/Status that
// presents the same hint derive the SAME Key and address the SAME row. It is NOT a
// raw passthrough of the hint: the hint is folded into a host-versioned,
// length-prefixed pre-image and hashed, so the handle this function emits is a
// host-derived value, not the body string.
//
// Namespace isolation does NOT live here — it lives in registry.DeriveKey, which
// mixes the host-resolved owner Identity into the key pre-image with length
// prefixes, so two callers presenting the same hint get DIFFERENT keys and a
// crafted hint can never escape the caller's namespace via a delimiter. The hint
// therefore stays a HINT (it only ever addresses a row WITHIN the owner's
// namespace), never an authority. A request body cannot become the Key: the body
// only reaches this deterministic host transform, and DeriveKey is the sole Key
// producer.
func mintHandle(hint string) string {
	h := sha256.New()
	writeHandleField(h, handleVersion)
	writeHandleField(h, hint)
	return hex.EncodeToString(h.Sum(nil))
}

// writeHandleField appends one length-prefixed field to the handle pre-image: an
// 8-byte big-endian length, then the raw bytes. The fixed-width prefix means a hint
// containing any byte cannot be confused for a field boundary, so the version tag
// and the hint can never straddle.
func writeHandleField(h hash.Hash, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	// A hash.Hash Write never returns an error; both writes are unconditional.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

// Destroy resolves the host-derived identity from caller, derives the Key from the
// host-minted handle the hint addresses, audience-scoped-looks-up the row via the
// Custodian (ErrNotOwned for a non-owned or absent row, indistinguishable from
// not-found so a forge attempt cannot probe existence), emits the destroy audit
// record (fail-closed: a write failure denies the destroy), runs the Teardown
// finalizer with a drain window, Releases the reservation, and decrements the
// per-tenant concurrent-session level counter through ReleaseConcurrency (the SAME
// decrement the reconciler uses). A foreign sessionHint yields ErrNotOwned, never
// the victim's teardown.
func (m *Manager) Destroy(ctx context.Context, caller ingress.AuthenticatedCaller, sessionHint string) error {
	owner := caller.Identity
	if owner.Caller == "" || owner.Tenant == "" {
		return ErrUnattested
	}
	// The body hint only ADDRESSES the row through the derived key; owner is the
	// host-derived authority the row is gated on. The same deterministic host
	// transform the create used (mintHandle) re-derives the handle, then DeriveKey
	// mixes the owner Identity in — so a foreign caller deriving from the same hint
	// lands on a DIFFERENT key (its own namespace) and can never address the victim's
	// row.
	key := registry.DeriveKey(owner, mintHandle(sessionHint))

	row, err := m.reg.LookupForCaller(ctx, key, owner)
	if err != nil {
		// ErrNotOwned (and a collapsed not-found) propagate unchanged: the caller
		// cannot distinguish "absent" from "exists but not yours".
		return fmt.Errorf("lifecycle: destroy lookup: %w", err)
	}

	// Audit FIRST, fail-closed: a destroy is a privileged op, so its record must be
	// durable before the teardown is acknowledged. A write failure denies the
	// destroy and touches no substrate.
	rec := audit.Record{
		Action:  audit.ActionDestroy,
		Channel: caller.Channel.String(),
		Key:     key.String(),
		Caller:  owner.Caller,
		Tenant:  owner.Tenant,
	}
	if err := m.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("lifecycle: destroy audit: %w", err)
	}

	// ADVISORY control-RPC nudge BEFORE the authoritative finalizer (ADR-0018). The
	// host dials the guest's control UDS to advance the cooperative SIGTERM phase;
	// the dial is best-effort and its result is SWALLOWED — a gate refusal, an
	// unattested/empty-name reject, a connect-refused, a timeout, a non-accept reply,
	// or a guest ControlError can at most nudge the guest, NEVER reorder, substitute,
	// or mark-complete the finalizer. The host-driven finalizer below (NFR-SEC-65) is
	// authoritative and never waits on this reply, so an unreachable control channel
	// grants the guest no new authority (NFR-SEC-01). A nil dialer (Phase-3 minimal
	// shelf) is a clean no-op.
	//
	// SOCKDIR PROVENANCE: the session row does not persist HostSockDir, so it is
	// re-derived PURELY from the host-derived session key — the SAME pure function the
	// create-path handoff stager used (handoff.Stager.SockDir(name), base/<name>/sock)
	// — exactly as the finalizer re-derives every resource name from SessionName. The
	// body hint never reaches this: name is runtime.SessionName(row.Key), host-derived
	// (NFR-SEC-43). The container_name the dial binds the exec JWT to is the
	// host-attested row.ContainerName, never a body value.
	if m.controlDialer != nil && row.ContainerName != "" {
		sockDir := m.handoff.SockDir(runtime.SessionName(row.Key))
		// The error is intentionally swallowed: the advisory dial is non-authoritative
		// for teardown and the pure-domain Manager holds no transport or logger. The
		// blank assignment makes the deliberate swallow explicit and greppable, mirroring
		// the finalizer's own swallow of its non-authoritative drain error.
		_ = m.controlDialer.Shutdown(ctx, sockDir, row.ContainerName)
	}

	// Run the host-driven teardown finalizer with a drain window. The finalizer is
	// detached and bounded internally; a wedged daemon call cannot strand a half-freed
	// session. ErrNoSuchContainer is idempotent (already-gone), not a failure.
	// The teardown Sandbox carries the host-derived session key on
	// Egress.FilesystemID so the below-seam finalizer step-1 (revoke session JWT)
	// can look up the jti the create-path mint recorded against that same key. The
	// frozen session row does not persist the real filesystem_id, so the revocation
	// handle is the session key the create and destroy paths both derive — never a
	// body hint (NFR-SEC-43; the in-memory Revoker index is the durable record's
	// later-phase concern).
	sandbox := runtime.Sandbox{
		Name:      runtime.SessionName(row.Key),
		RuntimeID: row.ContainerName,
		Egress:    runtime.EgressBinding{Name: runtime.SessionName(row.Key), FilesystemID: row.Key},
		Tier:      m.tier,
	}
	if err := m.provider.Teardown().GracefulStop(ctx, sandbox, destroyGrace); err != nil {
		if !errors.Is(err, runtime.ErrNoSuchContainer) {
			return fmt.Errorf("lifecycle: destroy teardown: %w", err)
		}
	}

	// Release the reservation to the RELEASED tombstone, then return the per-tenant
	// concurrent level counter through the shared decrement path.
	if _, err := m.reg.Release(ctx, key, owner); err != nil {
		return fmt.Errorf("lifecycle: destroy release: %w", err)
	}
	if err := m.ReleaseConcurrency(ctx, owner); err != nil {
		return fmt.Errorf("lifecycle: destroy release concurrency: %w", err)
	}
	// The destroy succeeded (released and capacity returned). Record it for the
	// admin /metrics surface — observational, after the fact.
	if m.metrics != nil {
		m.metrics.IncDestroy()
	}
	// Publish the live-view delta (the session reached RELEASED) to the
	// design-fenced fan-out — non-fatal, nil-safe; the console removes the row from
	// its live view when SSE is wired.
	m.publishEvent(ctx, state.StateReleased, key.String())
	return nil
}

// Status returns the caller's OWN session row addressed by sessionHint, through
// the same host-derived handle→Key derivation Create and Destroy use, and the
// Custodian's audience-scoped LookupForCaller. A foreign or absent row yields
// registry.ErrNotOwned (indistinguishable from not-found), so a caller can neither
// read another tenant's session nor probe its existence (NFR-SEC-43). It is a pure
// read: it audits nothing and mutates nothing. The body hint only ADDRESSES the
// caller's own namespace; owner is the host-derived authority. An empty host
// identity is refused fail-closed before any Store read.
func (m *Manager) Status(ctx context.Context, caller ingress.AuthenticatedCaller, sessionHint string) (state.SessionRow, error) {
	owner := caller.Identity
	if owner.Caller == "" || owner.Tenant == "" {
		return state.SessionRow{}, ErrUnattested
	}
	key := registry.DeriveKey(owner, mintHandle(sessionHint))
	row, err := m.reg.LookupForCaller(ctx, key, owner)
	if err != nil {
		return state.SessionRow{}, fmt.Errorf("lifecycle: status lookup: %w", err)
	}
	return row, nil
}

// ReleaseConcurrency is the SINGLE per-tenant DimConcurrentSessions decrement that
// BOTH Destroy and the boot reconciler call, so a crashed-then-reclaimed RESERVED
// row does not leak the level counter upward (the reconciler→quota coupling). It is
// a negative-delta Charge of the level cell, which the Store saturates at zero, so a
// double decrement never drives the counter negative. The decrement runs detached
// and bounded so a cancelled request context cannot strand the counter above the
// true live count.
func (m *Manager) ReleaseConcurrency(ctx context.Context, tenant state.Identity) error {
	if err := m.quota.RefundConcurrent(ctx, tenant); err != nil {
		return fmt.Errorf("lifecycle: release concurrency: %w", err)
	}
	return nil
}

// Reconcile is the boot orphan sweep. It lists substrate orphans via
// provider.Reconcile and force-kills each (idempotent; an already-gone container is
// a satisfied kill). It then enumerates the live (RESERVED+ACTIVE) registry rows
// via the Custodian and, for every reclaimed RESERVED row, Releases it AND calls
// ReleaseConcurrency, so a crashed-mid-create RESERVED row leaves no level-counter
// leak. A Store with no enumeration capability surfaces
// registry.ErrEnumerationUnsupported, which is fail-closed (the sweep refuses to
// claim it reconciled rows it could not even list).
func (m *Manager) Reconcile(ctx context.Context) error {
	// ONE pre-sweep snapshot of the live substrate. Both diff-sets below evaluate
	// against THIS listing, taken BEFORE any kill: snapshotting after the kills would
	// make every row's container look gone and self-inflict a Lost reclaim on every
	// session (the wedge in disguise). Session rows are durable, containers ephemeral —
	// the reconciler restores the two-way agreement between them.
	live, err := m.provider.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: reconcile list substrate: %w", err)
	}
	liveByName := make(map[runtime.SessionName]runtime.Sandbox, len(live))
	for i := range live {
		liveByName[live[i].Name] = live[i]
	}

	rows, err := m.reg.ReservedAndActiveKeys(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: reconcile list rows: %w", err)
	}
	rowKeys := make(map[runtime.SessionName]bool, len(rows))
	for i := range rows {
		rowKeys[runtime.SessionName(rows[i].Key)] = true
	}

	// Direction 1 — substrate without a LIVE row-backed session → destroy. A container
	// whose row is absent (or already terminal) is a true orphan: crashed-mid-create
	// residue, or a container whose row this same sweep reclaims below. A container
	// that IS matched to a row but has EXITED (Alive false) is ALSO swept: its row is
	// reclaimed in Direction 2, so leaving the dead container behind would trade the
	// slot leak for a container-garbage leak. Only a RUNNING container matched to a row
	// is a live session and is never killed. Force-kill is idempotent; an already-gone
	// container is a satisfied kill.
	finalizer := m.provider.Teardown()
	for i := range live {
		if rowKeys[live[i].Name] && live[i].Alive {
			continue // matched to a row AND running: a live session, never killed
		}
		if err := finalizer.ForceKill(ctx, live[i]); err != nil {
			if !errors.Is(err, runtime.ErrNoSuchContainer) {
				return fmt.Errorf("lifecycle: reconcile force-kill orphan %q: %w", live[i].Name, err)
			}
		}
	}

	// Direction 2 — non-terminal row without a LIVE backing container → reclaim. A
	// RESERVED row whose create crashed before Commit, an ACTIVE row whose container
	// vanished out-of-band (host crash, OOM-kill, external removal), OR a row whose
	// container is still PRESENT but has EXITED, has lost its live backing resource
	// while still holding a concurrency slot. A present-but-!Alive container is
	// substrate-lost exactly like an absent one: the boot sweep lists exited containers
	// too, and one must not wedge its row's slot. Reclaim: emit the system-initiated
	// reconcile-reclaim audit event (fail-closed, NFR-SEC-72), release the row to the
	// tombstone, and return the slot so the leak cannot wedge the tier cap. Only an
	// ACTIVE row WITH a RUNNING container is a live session, left untouched (slot stays
	// charged); Direction 1 above force-killed the exited container, so no garbage is
	// left behind for the row this reclaims.
	for i := range rows {
		sb := liveByName[runtime.SessionName(rows[i].Key)]
		if sb.Name != "" && sb.Alive {
			continue // substrate present AND running: a live session, keep its slot
		}
		if err := m.reclaimOrphanRow(ctx, rows[i]); err != nil {
			return fmt.Errorf("lifecycle: reconcile reclaim orphan row %q: %w", rows[i].Key, err)
		}
	}

	// Direction 3 — heal any DimConcurrentSessions cell drift. The cell is a separate
	// lock domain from the rows, moved only by +1 charge / -1 refund; a refund lost to a
	// swallowed unwind error (an aborted create whose Receipt.Apply failed) leaves the
	// cell ABOVE the true live count with no row to reclaim, so Direction 2 cannot
	// correct it — the counter over-counts until it wedges the tier cap with zero live
	// rows. Recompute the truth from the rows that SURVIVE the sweep — an ACTIVE row
	// WITH a live, running container — and correct each tenant's cell down to that count.
	// A row Direction 2 just reclaimed, or an ACTIVE row whose container is gone, is NOT
	// live and does not count. This makes a restart restore cell-truth regardless of past
	// refund reliability. It only corrects DOWN (ReconcileConcurrent never inflates), so
	// a genuine live session keeps its charge.
	liveByTenant := make(map[state.Identity]int64)
	for i := range rows {
		sb := liveByName[runtime.SessionName(rows[i].Key)]
		isLive := rows[i].State == state.StateActive && sb.Name != "" && sb.Alive
		if _, seen := liveByTenant[rows[i].Owner]; !seen {
			liveByTenant[rows[i].Owner] = 0
		}
		if isLive {
			liveByTenant[rows[i].Owner]++
		}
	}
	for owner, liveCount := range liveByTenant {
		if _, err := m.quota.ReconcileConcurrent(ctx, owner, liveCount); err != nil {
			return fmt.Errorf("lifecycle: reconcile concurrency cell for %q: %w", owner.Tenant, err)
		}
	}
	return nil
}

// reclaimOrphanRow reclaims one non-terminal row whose live backing container the boot
// sweep found absent or exited (substrate-lost). It is AUDIT-FIRST and fail-closed: the
// system-initiated reconcile-reclaim record is emitted BEFORE the row is released, so a
// slot returned to the tier cap is never returned un-recorded (NFR-SEC-72). It then
// releases the row to the tombstone and returns the concurrency slot through the SAME
// single decrement the destroy path uses. The row carries its own opaque Store key and
// host-derived owner; the reconciler is not audience-scoped (only the boot path reaches
// this), so it acts by the row's own identity. Release and ReleaseConcurrency are
// idempotent, so a re-run of the reconciler never double-credits.
func (m *Manager) reclaimOrphanRow(ctx context.Context, row state.SessionRow) error {
	rec := audit.Record{
		Action: audit.ActionReconcileReclaim,
		Key:    row.Key,
		Caller: row.Owner.Caller,
		Tenant: row.Owner.Tenant,
		Reason: "substrate-lost: boot reconciler found no live container for a non-terminal session row",
	}
	if err := m.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("reconcile-reclaim audit: %w", err)
	}
	if _, err := m.reg.ReleaseRow(ctx, row); err != nil {
		return fmt.Errorf("release reclaimed row: %w", err)
	}
	if err := m.ReleaseConcurrency(ctx, row.Owner); err != nil {
		return fmt.Errorf("release reclaimed concurrency: %w", err)
	}
	return nil
}

// ReapIdle reclaims every ACTIVE session whose last activity is older than idleTTL —
// an abandoned session (the client crashed, dropped, or was OOM-killed without
// calling destroy) whose container is still Up so neither the boot reconciler
// (substrate-lost only) nor the kill-switch (operator-driven) reclaims it. Without
// this a session with no client holds its concurrency slot forever, wedging the tier
// cap: a fail-open DoS. It returns the number of sessions reaped.
//
// The idle window is measured entirely through the injected Clock: LastActivity is a
// Clock stamp (set at activation, advanced on every exec), and idleness is
// Clock.Now() minus that stamp — two in-process Clock readings, never a persisted-
// timestamp subtraction, so a wall-clock setback moves no reclaim (NFR-SEC-48). A
// row with no LastActivity (still RESERVED, or a Store without the enrichment) is
// skipped: only a committed ACTIVE session with a recorded activity stamp is a reap
// candidate, so a crashed-mid-create RESERVED row is left to the boot reconciler.
//
// Each reap is AUDIT-FIRST and fail-closed: the system-initiated reconcile-reclaim
// record (idle-reap cause, NFR-SEC-72) is emitted BEFORE the row is released, so a
// slot returned to the tier cap is never returned un-recorded. A Store that cannot
// enumerate enriched rows surfaces the typed error (fail-closed — the reaper refuses
// to claim it reaped rows it could not list).
func (m *Manager) ReapIdle(ctx context.Context, idleTTL time.Duration) (int, error) {
	rows, err := m.reg.EnrichedLiveSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("lifecycle: reap-idle list rows: %w", err)
	}
	now := m.clk.Now()
	reaped := 0
	for i := range rows {
		r := rows[i]
		// Only a committed ACTIVE session with a recorded activity stamp is a reap
		// candidate. A RESERVED row (crashed mid-create) is the boot reconciler's; a row
		// with no stamp cannot be measured for idleness, so it is left alone.
		if r.State != state.StateActive || r.LastActivity == nil {
			continue
		}
		if now.Sub(*r.LastActivity) <= idleTTL {
			continue // recent activity: a live session, keep its slot
		}
		if err := m.reapOne(ctx, r.SessionRow); err != nil {
			return reaped, fmt.Errorf("lifecycle: reap-idle %q: %w", r.Key, err)
		}
		reaped++
	}
	return reaped, nil
}

// reapOne reclaims one idle ACTIVE row. It is AUDIT-FIRST and fail-closed: the
// reconcile-reclaim record (idle-reap cause) is emitted BEFORE any teardown or
// release, so a slot returned to the tier cap is never returned un-recorded
// (NFR-SEC-72). It then FORCE-KILLS the substrate, then releases the row to the
// tombstone and returns the concurrency slot through the SAME single decrement the
// destroy and boot-reconcile paths use.
//
// The teardown runs BEFORE the release, not after: a reap that returned the slot
// first would let a fresh create claim that slot and materialize a new guest while
// the abandoned container is still breathing — a slot-reuse-while-orphan-lives race.
// The finalizer verb is ForceKill, not the cooperative GracefulStop the destroy path
// uses: a reaped session is abandoned by definition (its client vanished), so there
// is no cooperative peer to drain and no advisory control-RPC nudge to send — the
// host-driven kill is authoritative (NFR-SEC-01). The teardown target is built PURELY
// from the host-derived row (Name from the session key, RuntimeID from the write-once
// bound row.ContainerName), the same construction Destroy uses; no body hint reaches
// it (NFR-SEC-43). An already-gone container is idempotent (ErrNoSuchContainer is a
// satisfied kill), exactly as the boot reconciler's orphan sweep treats it, so a
// re-run of the reaper never fails on a container a prior tick already removed.
// Release and ReleaseConcurrency are likewise idempotent, so a re-run never
// double-credits.
func (m *Manager) reapOne(ctx context.Context, row state.SessionRow) error {
	rec := audit.Record{
		Action: audit.ActionReconcileReclaim,
		Key:    row.Key,
		Caller: row.Owner.Caller,
		Tenant: row.Owner.Tenant,
		Reason: "idle-reap: session idle past the idle-TTL with no exec or control activity",
	}
	if err := m.audit.Emit(ctx, rec); err != nil {
		return fmt.Errorf("idle-reap audit: %w", err)
	}
	// Force-kill the abandoned substrate BEFORE returning the slot. The sandbox is
	// re-derived from the host-attested row exactly as Destroy builds it — the session
	// key names the container and the write-once bound container name is its runtime id.
	sandbox := runtime.Sandbox{
		Name:      runtime.SessionName(row.Key),
		RuntimeID: row.ContainerName,
		Egress:    runtime.EgressBinding{Name: runtime.SessionName(row.Key), FilesystemID: row.Key},
		Tier:      m.tier,
	}
	if err := m.provider.Teardown().ForceKill(ctx, sandbox); err != nil {
		if !errors.Is(err, runtime.ErrNoSuchContainer) {
			return fmt.Errorf("idle-reap force-kill: %w", err)
		}
	}
	if _, err := m.reg.ReleaseRow(ctx, row); err != nil {
		return fmt.Errorf("release reaped row: %w", err)
	}
	if err := m.ReleaseConcurrency(ctx, row.Owner); err != nil {
		return fmt.Errorf("release reaped concurrency: %w", err)
	}
	return nil
}
