// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package runtime defines the RuntimeProvider seam: the single contract the
// control plane welds container lifecycle to. Control logic depends on this
// interface only — never on a concrete container SDK type. Docker is the v1
// backend; a Kubernetes backend and a Firecracker backend land later behind
// this exact interface. The Docker SDK (github.com/docker/docker/client) is
// imported by exactly one package — the Docker provider impl — and CI greps the
// tree to keep client.APIClient out of every other package (requirement 1).
//
// The seam covers the four runtime responsibilities component-02 names
// (requirement 2):
//
//   - (a) create/run a sandbox container — Materialize;
//   - (b) the per-session storage mount the rclone-filestore guest consumes —
//     carried into Materialize as MountIntent on the SessionSpec, materialized
//     below the seam (a Docker bind / a k8s volume). Phase 2 defines the shape
//     and a Docker materialization, not the full mount-push wire (Phase 4);
//   - (c) the Envoy egress trust-edge wiring for the session — carried into
//     Materialize as EgressPolicy on the SessionSpec, materialized below the
//     seam (a per-session Internal bridge under Docker; a NetworkPolicy + SDS
//     under k8s). Materialize returns the EgressBinding handle the finalizer
//     later revokes — the route drop is a distinct verb, never "configure the
//     policy to empty". Phase 2 defines the shape; the real SDS lands later;
//   - (d) teardown — the RuntimeTeardown finalizer (GracefulStop / ForceKill).
//
// SEAM SHAPE (the resolved fork). "create" is ONE coarse Materialize(ctx, spec)
// that does network + container + start atomically with internal rollback, not
// three discrete provider primitives. The network create/remove pair lives
// BELOW the seam, inside the Docker impl — it never appears on this interface,
// because Kubernetes has no per-session bridge to create (a k8s Materialize
// makes a Pod + NetworkPolicy). A coarse seam is the only k8s-portable boundary:
// a fine NetworkCreate/ContainerCreate/ContainerStart triple would leak the
// Docker object model onto the interface and force the k8s impl to emulate a
// bridge it does not have. The whole substrate difference (bridge vs Pod, bind
// vs PVC, inline SDS vs xDS) is hidden behind one atomic call that takes a
// substrate-neutral SessionSpec and returns a substrate-neutral Sandbox handle.
//
// The provider owns NO state. internal/state holds the reservation registry,
// deny posture, and quota; the lifecycle code above the provider (Phase 3)
// drives Materialize after Reserve/Commit and the finalizer after Release. In
// Phase 2 the provider is exercised directly by tests.
//
// Each method below traces to a numbered requirement; no requirement is left
// without a method, and no method exists that a requirement does not force.
package runtime

import (
	"context"
	"errors"
)

// SchemaVersion pins the wire-shape of the substrate-neutral descriptor the
// control plane hands across the seam. A breaking change increments it; a
// provider rejects a spec whose version it does not understand BEFORE any
// substrate call (fail-closed). It is a label, not a comparison subject for any
// security decision.
type SchemaVersion string

// SchemaV1Alpha is the Phase-2 descriptor version.
const SchemaV1Alpha SchemaVersion = "v1alpha"

// RuntimeTier is the deployment-wide isolation tier selector (requirement 5,
// tier selector). It is set once for the whole deployment from -runtime-tier and
// is NEVER per-request: a SessionSpec does not carry a tier, the provider is
// constructed bound to one. It stays ORTHOGONAL to the provider choice
// (-runtime-provider): the provider is WHO materializes (docker | k8s), the tier
// is the kernel-isolation strength the chosen provider asks its substrate for
// (runc | gvisor | firecracker). They do not fold together — k8s+gvisor and
// docker+gvisor are both valid, and the same TierFirecracker abort rule holds
// under either provider until that provider implements it.
type RuntimeTier uint8

const (
	// TierRunc is the stock OCI runtime (a shared-kernel namespace boundary).
	TierRunc RuntimeTier = iota
	// TierGvisor is the user-space-kernel runtime (a syscall-interception
	// boundary, stronger than runc).
	TierGvisor
	// TierFirecracker is the microVM runtime (a hardware-virtualization
	// boundary). The v1 Docker provider does not wire it: Materialize ABORTS with
	// ErrNotImplemented rather than silently fall back to a weaker tier
	// (requirement 5 — no insecure fallback), and issues ZERO substrate calls.
	TierFirecracker
)

// Duration is the grace window for GracefulStop, in WHOLE SECONDS. It is an int,
// not a time.Duration: the Docker ContainerStop timeout is integer seconds
// (StopOptions.Timeout is *int seconds), so a time.Duration on the signature
// would be a live nanoseconds-vs-seconds unit-conversion trap at the substrate
// boundary. The seam states seconds explicitly and the Docker impl passes the
// value straight through as *int. A zero Duration means "stop immediately, no
// drain window"; a negative value means "wait indefinitely".
type Duration int

// Identity is re-declared at the seam as a local type to avoid a hard dependency
// from internal/runtime onto internal/state, keeping the provider a leaf seam.
// The lifecycle layer maps state.Identity into this before calling the provider;
// a compile-time field-parity test (Phase 3) and a single mapping function keep
// the two from drifting. It is the host-derived caller identity: the
// runtime-attested principal, never a body-supplied hint (NFR-SEC-43). The
// provider treats it as opaque labelling material — it derives no authority.
type Identity struct {
	// Tenant is the host-resolved tenant the session is billed against.
	Tenant string
	// Caller is the host-resolved principal that issued the create.
	Caller string
}

// SessionName is the host-derived session identity (body id is a hint, never
// authority, NFR-SEC-43). It is a PURE FUNCTION INPUT for every derived resource
// name the provider computes — the per-session bridge name, the container name,
// the sock-dir path — so teardown can re-derive the exact same names from the
// SessionName alone without consulting any provider state (requirement 5 —
// "Name is a pure function of the session name so destroy derives it"). The same
// purity lets the orphan-sweep reconciler re-derive a Sandbox from a label and
// the Name after a controller crash mid-Materialize.
type SessionName string

// HandoffMaterial is the non-secret bytes the host bakes into the container at
// create so the in-guest control-RPC endpoint and the exec UDS can be reached
// (requirement 5 — HOST-01 Binds). The Ed25519 value is the PUBLIC key; the only
// secret (the storage-JWT) rides MountIntent, never this struct. The provider
// writes each as a host-owned :ro bind; it never synthesizes them.
type HandoffMaterial struct {
	// ContainerInfoJSON is the serialized container_info.json the guest reads at
	// boot. Written by the Stager to ContainerInfoHostPath and mounted :ro at
	// ContainerInfoGuestPath.
	ContainerInfoJSON []byte
	// ContainerInfoHostPath is the per-session host file the Stager actually wrote
	// the container_info.json bytes to — the SOURCE side of the :ro bind. It must
	// be a real path on the host filesystem; the daemon mounts it into the guest.
	ContainerInfoHostPath string
	// ContainerInfoGuestPath is the absolute in-guest mountpoint — the TARGET side
	// of the bind and the path the guest reads container_info.json from. It is the
	// guest image's hardcoded default, the filesystem root, so no read-path
	// override is supplied to the guest.
	ContainerInfoGuestPath string

	// PublicKeyEd25519 is the raw 32-byte Ed25519 PUBLIC key (NOT a secret) the
	// guest uses to verify host-signed control-RPC frames. Written by the Stager
	// to PublicKeyHostPath and mounted :ro at PublicKeyGuestPath. The provider
	// fails the create closed if it is not exactly 32 bytes — a malformed key is
	// never substituted by a daemon default.
	PublicKeyEd25519 []byte
	// PublicKeyHostPath is the per-session host file the Stager actually wrote the
	// public key to — the SOURCE side of the :ro bind. It must be a real path on
	// the host filesystem; the daemon mounts it into the guest.
	PublicKeyHostPath string
	// PublicKeyGuestPath is the absolute in-guest mountpoint — the TARGET side of
	// the bind and the value the guest is given via --auth-public-key, so the path
	// the guest reads the key from can never drift from the path the host mounts.
	PublicKeyGuestPath string

	// HostSockDir is the host-owned 0700 directory bind-mounted RW (no :ro) at
	// /run/ocu inside the guest, where the GUEST creates the exec UDS. The
	// provider does not pre-create the socket; it owns and locks down the dir.
	HostSockDir string
}

// MountIntent is the substrate-NEUTRAL per-session storage-mount description
// (requirement 2(b)). It is an INTENT, not a materialized mount-config: it names
// what the session needs (scope, RW/RO posture, the pre-issued weak Storage-JWT,
// the freshness window), and each provider materializes it — the Docker impl
// into a bind the rclone-filestore guest consumes; the k8s impl into a volume +
// projected secret. The k8s door forces the neutral intent — a docker bind path
// is meaningless to a Pod spec. Phase 2 fixes the shape; the real mount-config
// push (contracts/storage/mount-config.schema.json) is Phase 4.
type MountIntent struct {
	// Destination is the absolute guest mountpoint (e.g. /workspace/out).
	Destination string
	// FilesystemID is the per-session logical scope (the isolation unit). Egress
	// binds the connection to this id. Exactly one of FilesystemID /
	// MemoryStoreID is set.
	FilesystemID string
	// MemoryStoreID is the parallel scope for a memory-backed mount.
	MemoryStoreID string
	// ReadOnly is the host-enforced posture: true => RO input, false => RW sink.
	// The agent cannot flip it.
	ReadOnly bool
	// AuthToken is the pre-issued WEAK Storage-JWT, scoped to FilesystemID,
	// opaque to the holder. Control minted it; the egress edge exchanges it. This
	// is the one secret in the spec — the provider writes it into the mount
	// material, never into container Env (Env stays empty, requirement 5).
	AuthToken string
	// CacheSeconds is the per-mount local-VFS freshness window in whole seconds
	// (short for RO inputs, long for the RW sink). Carried neutrally as an int —
	// not a time.Duration — for the same seconds-vs-nanoseconds reason as
	// Duration; the provider maps it to the substrate's cache knob.
	CacheSeconds int
}

// EgressPolicy is the substrate-NEUTRAL per-session egress trust-edge
// description (requirement 2(c)). It is a POLICY, not a materialized Envoy SDS
// bundle: it states the deny-default posture and the single allow-listed
// upstream the session may reach through the trust-edge. The Docker impl
// materializes it as a per-session Internal bridge (deny-all outbound NAT) plus
// the trust-edge wiring; the k8s impl as a NetworkPolicy plus an SDS resource.
// The k8s door pushes the neutral policy — a Docker bridge name is meaningless
// to a NetworkPolicy. Phase 2 fixes the shape and a Docker materialization; the
// real Envoy SDS is later. Materialize returns the EgressBinding handle that
// names what was wired, so teardown drops the SAME route rather than
// re-deriving an empty policy.
type EgressPolicy struct {
	// DefaultDeny is the posture; it is true on every production path (the
	// control-plane bridge is Internal, deny-all). A provider rejects a spec with
	// DefaultDeny false on a production path — there is no permissive default.
	DefaultDeny bool
	// AllowedUpstream is the single allow-listed object-store service the mount
	// client may dial guest-out over the egress hop. Empty means no egress.
	AllowedUpstream string
	// FilesystemID binds the egress connection to the same scope as the mount, so
	// the trust-edge can key the credential exchange on it.
	FilesystemID string
}

// ResourceCaps are the HARD resource caps the provider stamps onto the runtime
// (requirement 5 — Resources). These are caps, not shares: CPU is a hard ceiling
// (NanoCPUs under Docker), never a relative weight (never CPUShares). The
// provider translates them to the substrate's hard-cap primitive.
type ResourceCaps struct {
	// CPUCores is the hard CPU ceiling in fractional cores. The Docker impl maps
	// it to NanoCPUs = CPUCores * 1e9, never CPUShares.
	CPUCores float64
	// MemoryBytes is the hard memory ceiling. The /tmp tmpfs counts against it.
	MemoryBytes int64
	// PidsLimit caps the process count (the cgroup pids controller). A nil value
	// means "unset" only on a non-production test path; production always sets it.
	PidsLimit *int64
}

// SessionSpec is the SUBSTRATE-NEUTRAL session descriptor Control hands across
// the seam (the resolved fork: Control hands a neutral descriptor, each impl
// materializes it — NOT Control producing a docker bind / SDS bundle). It is the
// complete input to Materialize: mount intent + egress policy + resource caps +
// handoff material, plus the host-derived names that drive every derived
// resource. It carries NO docker types, NO k8s types, NO tier (the tier is bound
// to the provider, not the request — requirement 5).
type SessionSpec struct {
	// SchemaVersion pins the descriptor shape. A provider rejects an unknown one
	// with ErrUnsupportedSpec before any substrate call (fail-closed).
	SchemaVersion SchemaVersion
	// Name is the host-derived session identity, the pure-function input for
	// every derived resource name (requirement 5).
	Name SessionName
	// Owner is the host-derived caller identity (labelling only; the provider
	// derives no authority from it — NFR-SEC-43).
	Owner Identity
	// Image is the sandbox container image reference the provider runs.
	Image string
	// Mounts are the per-session storage mounts to materialize (requirement
	// 2(b)). Each is a neutral intent.
	Mounts []MountIntent
	// Egress is the per-session egress trust-edge policy (requirement 2(c)).
	Egress EgressPolicy
	// Resources are the hard caps the provider stamps on (requirement 5).
	Resources ResourceCaps
	// Handoff is the non-secret material baked in as :ro binds + the RW sock dir
	// (requirement 5 — Binds).
	Handoff HandoffMaterial
}

// EgressBinding is the typed handle to the egress route Materialize wired for a
// session (graft: a real drop handle, not ConfigureEgress(empty)). The finalizer
// REVOKES this binding to drop the route host-side — "tear down the route" is a
// distinct verb from "configure the policy", so the no-route case is never
// conflated with the configure-to-nothing case. It is substrate-neutral: the
// FilesystemID and the host-derived Name are enough to re-derive the Docker
// bridge name or address the k8s SDS resource at teardown, so the binding
// survives a process restart without any provider state.
type EgressBinding struct {
	// Name is the host-derived session identity the route was wired for; the
	// provider re-derives the substrate route name from it at revoke time. It is
	// ALSO the key the finalizer step-1 revoke is looked up under (the same
	// host-derived identity the mint recorded the jti against), never FilesystemID.
	Name SessionName
	// FilesystemID is the scope the route was keyed on, dropped on teardown even
	// if the guest is unresponsive (NFR-SEC-27).
	FilesystemID string
}

// RevokeOutcome is the distinct result of a finalizer step-1 revoke, so the
// teardown can record WHAT happened rather than collapsing "marked dead",
// "already dead", and "nothing was bound" into one indistinguishable success. It
// lives in runtime (not cred) so the below-seam docker Revoker port can surface
// it without the provider importing the whole custody package.
type RevokeOutcome int

const (
	// RevokeNoneBound: no jti was bound to the session's bind-key. A satisfied
	// no-op for the teardown error, but recorded as its own outcome — the
	// fail-open case a silent success would hide.
	RevokeNoneBound RevokeOutcome = iota
	// RevokeMarkedDead: a live jti was found and marked dead by this call.
	RevokeMarkedDead
	// RevokeAlreadyDead: the bound jti was already revoked (idempotent re-run).
	RevokeAlreadyDead
)

// String renders the outcome as the stable audit label emitted under
// revoke_outcome.
func (o RevokeOutcome) String() string {
	switch o {
	case RevokeMarkedDead:
		return "marked_dead"
	case RevokeAlreadyDead:
		return "already_dead"
	default:
		return "none_bound"
	}
}

// Sandbox is the substrate-neutral HANDLE the lifecycle layer holds after a
// successful Materialize. It is the ONLY thing the lifecycle needs to drive
// teardown: it carries the host-derived Name (from which the provider re-derives
// every resource name), the provider-assigned runtime id (the container id under
// Docker; the Pod uid under k8s — opaque to the lifecycle, meaningful only to
// the provider that minted it), and the EgressBinding the finalizer revokes. The
// lifecycle records RuntimeID via the state.Store's BindContainerName as
// recorded data, never as authority. The handle holds NO docker type and NO open
// client; it is a value the lifecycle can persist and replay into Teardown
// across a process restart.
type Sandbox struct {
	// Name is the host-derived session identity. The provider re-derives the
	// bridge name, sock-dir path, and container name from it during teardown, so
	// teardown needs no other provider state (requirement 5 — destroy derives the
	// name).
	Name SessionName
	// RuntimeID is the provider-assigned runtime identity (Docker container id /
	// k8s Pod uid). Opaque to the lifecycle; the provider uses it as the
	// fast-path target and falls back to the Name-derived name if it is empty.
	RuntimeID string
	// Egress is the trust-edge route binding to revoke on teardown (requirement
	// 2(c) drop). Zero value means no egress was wired (no route to drop).
	Egress EgressBinding
	// Tier is the isolation tier the provider materialized under, echoed for
	// audit. It equals the provider's deployment-wide tier; it is informational.
	Tier RuntimeTier
}

// Sentinel errors. Callers match with errors.Is; implementations wrap with %w
// and never return a bare dynamic error for these conditions, so the lifecycle
// layer, the admission gate, and the finalizer can branch on a stable typed
// value (repo convention: sentinel + %w, mirroring internal/state).
var (
	// ErrNotImplemented is returned by every method of a provider whose backend
	// is not yet built (the k8s and Firecracker impls), and by the Docker
	// provider's Materialize when the deployment tier is TierFirecracker — the
	// door is open, the room is empty, and the create ABORTS rather than fall
	// back to a weaker tier (requirements 5, 6). On the TierFirecracker abort the
	// Docker provider issues ZERO substrate calls.
	ErrNotImplemented = errors.New("runtime: not implemented")
	// ErrNoSuchContainer is returned by ForceKill (and may surface from
	// GracefulStop) when the runtime has no container for the session — the
	// force-remove already happened or never landed. It is the typed mapping of
	// the underlying not-found (cerrdefs.IsNotFound under Docker) and makes
	// force-remove IDEMPOTENT: a finalizer re-run sees this and treats the step
	// as already-satisfied, never an error (requirement 3 — idempotent
	// force-remove).
	ErrNoSuchContainer = errors.New("runtime: no such container")
	// ErrNetworkActive is the typed mapping of the underlying conflict
	// (cerrdefs.IsConflict under Docker) when a network still has attached
	// endpoints. NETWORK removal is STRICTLY AFTER container force-remove (the
	// active-endpoints constraint); this sentinel is the typed evidence the
	// ordering was violated, and the finalizer/rollback swallow an already-gone
	// network as idempotent (requirement 4).
	ErrNetworkActive = errors.New("runtime: network has active endpoints")
	// ErrSeccompProfileMissing is the fail-closed sentinel for the embedded
	// deny-default seccomp profile being absent or unparseable (graft from D3).
	// The Docker provider refuses to construct rather than create any container
	// with the daemon default — NO container is ever created without the explicit
	// profile (requirement 5 — fail-closed, never the daemon default).
	ErrSeccompProfileMissing = errors.New("runtime: embedded seccomp profile missing or invalid")
	// ErrUnsupportedSpec is returned by Materialize when the SessionSpec is
	// malformed for a production path: an unknown SchemaVersion, a non-32-byte
	// Ed25519 key, a permissive EgressPolicy (DefaultDeny false), or a missing
	// HOST-01 bind. It is fail-closed and rejected BEFORE any substrate call: no
	// network and no container is created (requirement 5 — fail-closed, never the
	// daemon default).
	ErrUnsupportedSpec = errors.New("runtime: unsupported or malformed session spec")
	// ErrMaterialize wraps a substrate failure during Materialize AFTER internal
	// rollback has run, so the caller learns the create failed AND that no orphan
	// network/container survives (the no-orphan property — requirement: rollback
	// on a failed create).
	ErrMaterialize = errors.New("runtime: materialize failed (rolled back, no orphan)")
	// ErrTeardown wraps a substrate failure during a finalizer step. The
	// finalizer records it and continues to the next host-side step rather than
	// abort, so one failed step cannot strand a later resource (requirement 4 —
	// host-driven ordered finalizer).
	ErrTeardown = errors.New("runtime: teardown step failed")
)

// RuntimeProvider is the container-lifecycle seam (requirement 1). Control logic
// holds a value of this interface and never a concrete SDK type. The Docker
// provider is the v1 implementation; the k8s and Firecracker providers compile
// and return ErrNotImplemented from every method (requirement 6). A provider is
// constructed bound to one deployment-wide RuntimeTier; the tier is not on this
// interface because it is not per-request (requirement 5).
type RuntimeProvider interface {
	// Materialize creates the per-session network, creates the container, and
	// starts it — ATOMICALLY, as ONE coarse operation (the resolved seam-shape
	// fork: a single Materialize, not discrete NetworkCreate/ContainerCreate/
	// ContainerStart primitives). It first validates the spec and, on a malformed
	// production spec, returns ErrUnsupportedSpec having issued ZERO substrate
	// calls (fail-closed). If the deployment tier is TierFirecracker it ABORTS
	// with ErrNotImplemented having issued ZERO substrate calls (requirement 5 —
	// no insecure fallback). On any step failure after the first substrate call
	// it ROLLS BACK the already-created resources (remove the container, then the
	// network — network after container, the active-endpoints constraint) so no
	// orphan survives, and returns ErrMaterialize. It applies the HOST-01
	// hardened configuration VERBATIM (requirement 5): CapDrop ALL,
	// no-new-privileges + the embedded deny-default seccomp profile (fail-closed
	// — no container without the explicit profile; an absent/invalid embed is
	// ErrSeccompProfileMissing), ReadonlyRootfs, the bounded /tmp tmpfs, the three
	// :ro/RW binds, the per-session INTERNAL bridge, the hard resource caps, no
	// PortBindings, and empty Env. The per-session bridge create lives entirely
	// inside the Docker impl — it does NOT appear on this interface (k8s has no
	// per-session bridge). On success it returns a Sandbox handle carrying the
	// runtime id and the EgressBinding the finalizer revokes (requirements 2(a),
	// 2(c)).
	Materialize(ctx context.Context, spec SessionSpec) (Sandbox, error)

	// Teardown returns the RuntimeTeardown finalizer bound to this provider. It
	// is a method (not the provider itself implementing the two teardown verbs)
	// so the lifecycle holds a small, sharp handle whose only surface is the two
	// canon-fixed verbs, and a test can assert the finalizer's step order without
	// the create surface in scope (requirements 3, 4).
	Teardown() RuntimeTeardown

	// Reconcile is the orphan-sweep seam (graft from D2). At boot, or after a
	// controller crash mid-Materialize, the lifecycle calls it to enumerate
	// sessions the substrate still holds but whose Sandbox handle was lost across
	// the restart. The Docker impl lists containers by the ocu-session label and
	// re-derives a Sandbox (Name, RuntimeID, EgressBinding) from the label and
	// the pure-function names, so the finalizer can reclaim each orphan bridge +
	// container. A backend with no orphan concept returns an empty slice and nil.
	Reconcile(ctx context.Context) ([]Sandbox, error)
}

// RuntimeTeardown is the CANON-FIXED teardown surface (requirement 3). Its two
// verbs are the only way the host reclaims a session. BOTH run the host-driven
// ordered finalizer (requirement 4) under context.WithoutCancel internally, each
// finalizer step further wrapped in a per-step bounded timeout derived from that
// detached base, so neither a cancelled parent context NOR a wedged daemon call
// can strand a half-freed session: revoke the session JWT, drop the
// network-bound egress route host-side via the EgressBinding (even if the guest
// is unresponsive — NFR-SEC-27), zero tmpfs/scratch, unmount the data scope,
// kill the process tree, destroy the cgroup. NETWORK removal is STRICTLY AFTER
// container force-remove (the active-endpoints constraint). No step depends on
// guest cooperation. The difference between the two verbs is ONLY the drain
// window before the kill step.
type RuntimeTeardown interface {
	// GracefulStop runs the finalizer with a SIGTERM-then-kill drain window of
	// grace seconds before the kill step: under Docker it is ContainerStop with
	// the timeout, giving the guest grace to flush before the host kills it. Every
	// other finalizer step (JWT revoke, egress-route drop, tmpfs zero, unmount,
	// cgroup destroy) runs host-side regardless of whether the guest honored the
	// SIGTERM. It is idempotent against an already-gone container
	// (ErrNoSuchContainer is treated as a satisfied kill step, not an error)
	// (requirements 3, 4).
	GracefulStop(ctx context.Context, sess Sandbox, grace Duration) error

	// ForceKill runs the finalizer with NO drain window: it skips straight to the
	// kill step (force-remove the container), which SUBSUMES any drain a
	// GracefulStop would have given (requirement 4 — a force-kill that skips drain
	// is acceptable). It is FORCE-REMOVE-AUTHORITATIVE: it NEVER waits on a guest
	// reply, and it is IDEMPOTENT — an underlying not-found (cerrdefs.IsNotFound)
	// maps to ErrNoSuchContainer and is treated as a satisfied kill, so a
	// re-invoked finalizer never errors on the missing container. Network removal
	// still follows the container force-remove (requirements 3, 4).
	ForceKill(ctx context.Context, sess Sandbox) error
}
