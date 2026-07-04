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
	Mount runtime.MountIntent
	// Egress is the per-session egress trust-edge policy.
	Egress runtime.EgressPolicy
	// Resources are the hard caps the provider stamps onto the runtime.
	Resources runtime.ResourceCaps
	// ControlPubKey is the raw 32-byte Ed25519 PUBLIC key the handoff stages for the
	// guest to verify host-signed control-RPC frames. The host mints it; a non-32-byte
	// value fails the create closed at the stageHandoff stage.
	ControlPubKey []byte
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
	// minted under (workspace/org/intent/downloadable). It is NEVER sourced from a
	// request body (NFR-SEC-43).
	StorageScope StorageScope

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

	// Storage-JWT custody + mount-config provisioning (Phase 4). signer/push are nil
	// on the Phase-3 minimal shelf, which the mint+render stages skip cleanly.
	signer        *cred.Signer
	push          provisioning.Pusher
	serviceURL    string
	caCertPEM     string
	mountDefaults mountcfg.MountDefaults
	storageScope  StorageScope

	// controlDialer is the advisory host-dialled control-RPC surface Destroy nudges
	// before the authoritative finalizer. nil is a clean no-op.
	controlDialer ControlDialer

	// execDriver is the guest exec-channel driver the gateway exec verb routes
	// through. nil makes Exec a fail-closed refusal.
	execDriver ExecDriver

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

		signer:        deps.Signer,
		push:          deps.Push,
		serviceURL:    deps.ServiceURL,
		caCertPEM:     deps.CACertPEM,
		mountDefaults: deps.MountDefaults,
		storageScope:  deps.StorageScope,
		controlDialer: deps.ControlDialer,
		execDriver:    deps.ExecDriver,
		metrics:       deps.Metrics,
		events:        deps.Events,
	}
	// The mint + render/push stages slot AFTER stageHandoff and BEFORE
	// stageMaterialize: the host-owned bind must carry the mount-config before
	// stageMaterialize starts the container, so the in-guest mount client never
	// boots without it. The no-orphan property test re-derives its fault points
	// from this slice length, so the new compensators are exercised automatically.
	m.stages = []stage{
		{name: "resolveIdentity", run: stageResolveIdentity},
		{name: "admit", run: stageAdmit},
		{name: "quotaCharge", run: stageQuotaCharge},
		{name: "reserve", run: stageReserve},
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
	// storageToken is the freshly minted weak Storage-JWT the render stage carries
	// into the mount-config. It stays a secret cred.Token on the create state — it
	// never widens the frozen runtime.MountIntent.AuthToken string seam — and is
	// revealed only at the single mountcfg.Marshal boundary.
	storageToken cred.Token
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
	st := &createState{in: in}
	// The unwind stack grows as each stage succeeds; on a failure it is replayed in
	// reverse. A nil compensator (read-only stage) is never pushed.
	compensators := make([]compensator, 0, len(m.stages))

	for _, s := range m.stages {
		comp, err := s.run(ctx, m, st)
		if err != nil {
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
	// Step 1: force-kill every substrate orphan the provider still holds. The
	// finalizer is detached and bounded internally; an already-gone container is
	// idempotent.
	orphans, err := m.provider.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: reconcile list orphans: %w", err)
	}
	finalizer := m.provider.Teardown()
	for i := range orphans {
		if err := finalizer.ForceKill(ctx, orphans[i]); err != nil {
			if !errors.Is(err, runtime.ErrNoSuchContainer) {
				return fmt.Errorf("lifecycle: reconcile force-kill orphan %q: %w", orphans[i].Name, err)
			}
		}
	}

	// Step 2: reclaim crashed RESERVED rows so the level counter is corrected. A
	// RESERVED row whose create crashed before Commit must be Released and its
	// concurrent slot returned; an ACTIVE row is a live session and is left alone.
	rows, err := m.reg.ReservedAndActiveKeys(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: reconcile list rows: %w", err)
	}
	for i := range rows {
		if rows[i].State != state.StateReserved {
			continue
		}
		owner := rows[i].Owner
		// ReservedAndActiveKeys returns the raw Store row; re-address it through the
		// Custodian by re-deriving nothing — the row carries its own opaque key, so the
		// reconciler releases by the row's owner identity via the Custodian's
		// row-addressed release path.
		if err := m.releaseReclaimed(ctx, rows[i]); err != nil {
			return fmt.Errorf("lifecycle: reconcile release reclaimed %q: %w", rows[i].Key, err)
		}
		if err := m.ReleaseConcurrency(ctx, owner); err != nil {
			return fmt.Errorf("lifecycle: reconcile release concurrency %q: %w", rows[i].Key, err)
		}
	}
	return nil
}

// releaseReclaimed releases one reclaimed RESERVED row through the Custodian. The
// row carries its own opaque Store key and host-derived owner; the reconciler is not
// audience-scoped (only the boot path and the operator kill-switch reach this), so
// it releases by the row's own identity. Release is idempotent against an
// already-released row, so a re-run of the reconciler never double-credits.
func (m *Manager) releaseReclaimed(ctx context.Context, row state.SessionRow) error {
	if _, err := m.reg.ReleaseRow(ctx, row); err != nil {
		return err
	}
	return nil
}
