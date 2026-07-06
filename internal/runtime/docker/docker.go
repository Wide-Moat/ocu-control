// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package docker is the v1 RuntimeProvider backend. It is the ONLY package in the
// tree that imports the Docker client; a CI grep asserts no client.APIClient
// reference appears outside it (requirement 1). It materializes the substrate-
// neutral runtime.SessionSpec into the HOST-01 hardened container.HostConfig plus
// the per-session Internal bridge behind the coarse
// runtime.RuntimeProvider.Materialize, and maps the canon-fixed teardown pair
// (GracefulStop / ForceKill) onto the Docker SDK through one ordered finalizer
// body.
//
// SEAM ISOLATION. Every Docker SDK call the provider makes goes through the
// unexported dockerAPI interface, satisfied by client.APIClient at runtime and by
// a recording fake in tests. The SDK type (client.APIClient) is named only in
// NewDockerProvider's default-client path and in dockerAPI's compile-time
// assertion; control logic above the seam holds runtime.RuntimeProvider and never
// a Docker type.
//
// FAIL-CLOSED HARDENING. The deny-default seccomp profile is embedded with
// //go:embed and json.Compact-validated at package init; an absent or unparseable
// profile is a package-init panic (it can never be silently downgraded to the
// daemon default — requirement 5). validateSpec rejects a malformed production
// spec with ErrUnsupportedSpec BEFORE any substrate call, and the TierFirecracker
// abort issues ZERO substrate calls.
package docker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// Label keys the provider stamps on every materialized container so the
// orphan-sweep reconciler can re-derive a Sandbox after a controller crash
// mid-Materialize, using nothing but the labels and the pure-function names.
// They are recorded data, never authority (NFR-SEC-43): Reconcile re-derives the
// bridge/container names from labelSessionName, it never trusts a label to grant
// a session new scope.
const (
	// labelManaged marks a container as one this provider owns; the reconciler
	// filters on it so it never touches a foreign container.
	labelManaged = "ocu-session"
	// labelSessionName carries the host-derived SessionName, the pure-function
	// input the reconciler feeds back into networkName/containerName.
	labelSessionName = "ocu-session-name"
	// labelFilesystemID records the egress SCOPE (the real filesystem_id) as
	// recorded data, never authority (NFR-SEC-43). The reconcile-derived revoke
	// handle binds on the host-derived session key (labelSessionName == row.Key),
	// the key the create-path mint recorded the jti under — NOT this label — so the
	// scope and the revocation-record key stay distinct. The label is retained for
	// the Phase-4 egress route drop, which needs the real scope at teardown.
	labelFilesystemID = "ocu-filesystem-id"
)

// managedLabelValue is the constant value of labelManaged; the reconciler's list
// filter keys on the (key, value) pair.
const managedLabelValue = "true"

// Single-source guest sock-dir layout. The host binds the per-session 0700 sock
// dir RW at guestSockDir (buildHostConfig), and the guest's listener Cmd flags
// (buildContainerConfig) derive the exec/control socket paths from the SAME
// mountpoint — so the in-guest path "/run/ocu" lives in exactly one place and the
// bind target can never drift from the path the guest is told to listen on.
const (
	// guestSockDir is the in-guest mountpoint of the host-owned RW sock directory.
	guestSockDir = "/run/ocu"
	// execSockName is the exec-channel UDS filename inside guestSockDir; the guest
	// binds it under --listen-uds.
	execSockName = "exec.sock"
	// controlSockName is the advisory control-RPC UDS filename inside guestSockDir;
	// the guest binds it under --control-listen-uds (additive, ADR-0018).
	controlSockName = "control.sock"
	// mountReadyName is the ready-file filename inside guestSockDir the mount
	// boot-child creates once every mount is up; the guest gates serving on it.
	mountReadyName = "mount.ready"
	// mountBinGuestPath is the in-guest path of the co-located mount binary in the
	// assembled guest image — a cross-repo contract pinned in the guest image
	// (deploy/guest-image) and the guest INTEGRATION.md. It is the first
	// --boot-child-argv token for a storage-scoped session.
	mountBinGuestPath = "/ocu-rclone-filestore"
	// guestAgentBinPath is the in-guest path of the guest agent binary (PID 1). It
	// is the SAME cross-repo contract the assembled guest image pins as its
	// ENTRYPOINT (deploy/guest-image). The provider sets it EXPLICITLY as the
	// container Entrypoint rather than trusting the image metadata: the agent argv
	// (the Cmd below) is a control-owned contract, so a BYO image whose ENTRYPOINT
	// drifts — or is empty — must fail loudly at start (the runtime cannot find the
	// binary) instead of silently running Cmd[0] ("--listen-uds") as the executable.
	guestAgentBinPath = "/usr/local/bin/process_api"
)

// defaultSeccomp is the embedded deny-default seccomp profile, applied verbatim
// as the seccomp= SecurityOpt on every container. Provenance: seccomp/README.md.
//
//go:embed seccomp/default.json
var defaultSeccomp []byte

// compactSeccomp is the json.Compact-validated profile string. It is computed
// once at package init; a malformed profile is a fail-closed init panic — the
// provider never creates a container with the daemon default (requirement 5).
var compactSeccomp = mustCompact(defaultSeccomp)

// mustCompact json.Compact-validates the embedded seccomp profile at package
// init. A missing or unparseable embed is a fail-closed panic so the provider can
// never construct a container with the daemon default (requirement 5). The panic
// names ErrSeccompProfileMissing so the cause is unambiguous in a crash log.
func mustCompact(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		panic(fmt.Sprintf("docker: %v: embedded seccomp profile is not valid JSON: %v",
			runtime.ErrSeccompProfileMissing, err))
	}
	return buf.String()
}

// dockerAPI is the narrow surface of the Docker SDK the provider depends on — the
// seven methods the design's Docker mapping names. It exists so the provider is
// testable against a recording fake that observes call order without a daemon, and
// so the concrete client.APIClient is named in exactly one place. It is satisfied
// by client.APIClient (the compile-time assertion below) AND by the test fake.
type dockerAPI interface {
	NetworkCreate(ctx context.Context, name string, options network.CreateOptions) (network.CreateResponse, error)
	NetworkRemove(ctx context.Context, networkID string) error
	ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, platform *ocispecPlatform, containerName string) (container.CreateResponse, error)
	ContainerStart(ctx context.Context, containerID string, options container.StartOptions) error
	ContainerStop(ctx context.Context, containerID string, options container.StopOptions) error
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
	ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error)
}

// ocispecPlatform aliases the OCI platform type the SDK's ContainerCreate takes,
// so the dockerAPI signature matches client.APIClient exactly while keeping the
// import surface of this file legible. The provider always passes nil for it.
type ocispecPlatform = ocispec.Platform

// Revoker is the narrow below-seam port the finalizer step-1 (revoke session JWT)
// calls to mark a session's minted Storage-JWT dead host-side. It is satisfied by
// *cred.Revoker; naming only Revoke keeps the provider depending on the revoke
// effect, not the whole custody package. A nil Revoker (the Phase-3 minimal shelf)
// makes step-1 the prior no-op; the step still runs in order.
//
// Revoke returns a RevokeOutcome so the finalizer can surface WHAT happened
// (a jti marked dead, an idempotent already-dead re-run, or none_bound — a
// revoke that found no binding). none_bound is a satisfied no-op for the teardown
// error, but it is a distinct outcome the finalizer records via RevokeAuditor,
// never dissolved into a blanket success.
type Revoker interface {
	Revoke(ctx context.Context, bind runtime.EgressBinding) (runtime.RevokeOutcome, error)
}

// RevokeAuditor is the narrow seam the finalizer step-1 calls to record the
// revoke outcome as evidence. It is satisfied by the lifecycle audit path; a nil
// RevokeAuditor (the minimal shelf) records nothing, exactly as a nil Revoker
// leaves the revoke effect a no-op. Keeping it separate from the Revoker keeps
// the revoke EFFECT and its AUDIT independently wired.
type RevokeAuditor interface {
	RecordRevokeOutcome(ctx context.Context, sess runtime.EgressBinding, outcome runtime.RevokeOutcome)
}

// Provider is the Docker RuntimeProvider. It holds the SDK behind the dockerAPI
// seam and the deployment-wide isolation tier it was constructed bound to (the
// tier is not per-request — requirement 5). It owns NO per-session state; teardown
// re-derives every resource name purely from the Sandbox's SessionName, including
// the host-owned handoff root the finalizer scrubs in step 3, which is a pure
// function of SessionName under the deployment-fixed stagerBase.
type Provider struct {
	api  dockerAPI
	tier runtime.RuntimeTier
	// revoker is the below-seam Storage-JWT revocation index finalizer step 1
	// targets. nil leaves step 1 a host-side no-op (the step still runs in order).
	revoker Revoker
	// revokeAuditor records the finalizer step-1 revoke outcome as evidence. nil
	// records nothing (the minimal shelf), exactly as a nil revoker leaves the
	// revoke effect a no-op. Kept separate from revoker so the revoke effect and
	// its audit are independently wired.
	revokeAuditor RevokeAuditor
	// INTERIM: this shared-network attach deviates from ADR-0021 (host-side L3 egress
	// attach seam), which keeps every session on its per-session Internal bridge and
	// reaches the edge via a host-root-netns listener on the per-session bridge
	// gateway IP — structural (kernel-enforced) cross-session isolation, not a shared
	// network. The shim exists only because a runsc guest cannot reach Docker embedded
	// DNS; the ADR-0021 attach works under gVisor when the guest dials the literal
	// per-session gateway IP (proven). Converge to ADR-0021 and remove this shim per
	// open-computer-use#333.
	//
	// egressNetwork is the deployment-fixed docker network a STORAGE-scoped guest
	// attaches to so its co-located mount can reach the egress edge — the only
	// component on that network the guest may talk to (the edge is multi-homed:
	// this guest-facing network on one side, the credential-bearing upstream
	// network on the other, which the guest is never placed on). A pure-exec
	// session ignores it entirely and stays on its own per-session deny-all
	// Internal bridge. Empty (the minimal shelf / no storage deployment) leaves
	// every session on the per-session Internal bridge, exactly as before. It is a
	// provider-construction value, NEVER a per-request body field (NFR-SEC-43).
	egressNetwork string
	// edgeHost is the deployment-fixed IP the guest resolves the `edge` name to via
	// a static ExtraHosts entry. A gVisor (runsc) guest cannot reach docker's
	// embedded DNS resolver at 127.0.0.11, so the `edge` name in the mount-config
	// service_url (kept a NAME for TLS SAN verification) is resolved by this pinned
	// host entry instead. Only applied to a storage-scoped session on the egress
	// network; empty adds no entry.
	edgeHost string
	// stagerBase is the deployment-fixed host directory under which the create-path
	// handoff stager writes each per-session 0700 root (base/<SessionName>). It is a
	// PROVIDER CONSTRUCTION value — never a per-request body field (NFR-SEC-43) — so
	// finalizer step 3 (zeroTmpfs) re-derives base/<sess.Name> purely from the
	// host-derived SessionName and scrubs the credential-bearing tree. An empty
	// stagerBase (the minimal shelf where no handoff base is wired) leaves step 3 a
	// host-side no-op, exactly as a nil revoker leaves step 1.
	stagerBase string
}

var (
	_ runtime.RuntimeProvider = (*Provider)(nil)
	// The runtime SDK client satisfies the narrow dockerAPI seam; this assertion
	// is the single load-bearing reference that keeps the two signatures aligned.
	_ dockerAPI = (client.APIClient)(nil)
)

// Deps carries the provider's injectable collaborators. In production NewDockerProvider
// leaves API nil and constructs a real env-configured SDK client; a test injects a
// recording fake so the create/teardown call order is observable without a daemon.
type Deps struct {
	// API, when non-nil, is used as-is (the test-fake injection point). When nil,
	// NewDockerProvider builds a real client via client.NewClientWithOpts(FromEnv).
	API dockerAPI
	// Revoker is the below-seam Storage-JWT revocation index the finalizer step-1
	// calls. nil leaves step-1 the prior host-side no-op (the step still runs in
	// order); the daemon wires the shared *cred.Revoker here.
	Revoker Revoker
	// RevokeAuditor records the step-1 revoke outcome (marked_dead / already_dead /
	// none_bound) as evidence. nil records nothing (the minimal shelf). The daemon
	// wires the lifecycle audit path here.
	RevokeAuditor RevokeAuditor
	// StagerBase is the deployment-fixed host directory under which the create-path
	// handoff stager writes each per-session 0700 root. The daemon wires the SAME
	// base it constructs the handoff.Stager with, so finalizer step 3 (zeroTmpfs)
	// scrubs base/<SessionName> — the host-owned credential-bearing handoff tree. It
	// is a provider-construction value, NEVER a per-request body field (NFR-SEC-43).
	// Empty leaves step 3 a host-side no-op (the minimal shelf), exactly as a nil
	// Revoker leaves step 1.
	StagerBase string
	// EgressNetwork is the deployment-fixed docker network a STORAGE-scoped guest
	// joins so its mount can reach the egress edge (see Provider.egressNetwork).
	// Empty keeps every session on its own per-session Internal bridge.
	EgressNetwork string
	// EdgeHost is the deployment-fixed IP the guest's static `edge` ExtraHosts entry
	// resolves to, working around gVisor's inability to use the embedded DNS
	// resolver (see Provider.edgeHost). Empty adds no ExtraHosts entry.
	EdgeHost string
}

// NewDockerProvider builds the Docker provider bound to the deployment-wide
// isolation tier. When deps.API is nil it constructs a real SDK client from the
// environment (client.NewClientWithOpts(client.FromEnv)); a test passes a recording
// fake through deps.API so no daemon is required. The tier is fixed at construction
// and can never be weakened by a request (requirement 5).
func NewDockerProvider(tier runtime.RuntimeTier, deps Deps) (*Provider, error) {
	api := deps.API
	if api == nil {
		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			return nil, fmt.Errorf("docker: construct client: %w", err)
		}
		api = cli
	}
	return &Provider{api: api, tier: tier, revoker: deps.Revoker, revokeAuditor: deps.RevokeAuditor, stagerBase: deps.StagerBase, egressNetwork: deps.EgressNetwork, edgeHost: deps.EdgeHost}, nil
}

// networkName is the pure function from session name to per-session bridge name,
// so teardown and Reconcile derive the same name without a lookup (requirement 5,
// NFR-SEC-43).
func networkName(name runtime.SessionName) string { return "ocu-net-" + string(name) }

// containerName is the pure function from session name to container name.
func containerName(name runtime.SessionName) string { return "ocu-sess-" + string(name) }

// dockerRuntimeForTier maps the deployment-wide isolation tier — and, within
// TierGvisor, the per-session FUSE need — to the Docker HostConfig.Runtime string.
// Empty means "the daemon default" (runc under a stock dockerd) — it is correct
// NOT to hardcode "runc", since the daemon may name its default differently.
// TierGvisor asks dockerd for the gVisor sentry; without this the gVisor admission
// decision is not enforced at the OCI layer (admission admits internal_workforce
// and untrusted-tier workloads on TierGvisor expecting the sentry, but a container
// created on the daemon default lands on a shared-kernel runc boundary).
// TierFirecracker never reaches here (Materialize aborts before buildHostConfig)
// so it has no arm and falls into the safe empty-string default.
//
// A gVisor host registers two runsc runtimes: "runsc" (the plain sentry) and
// "runsc-fuse" (the sentry started with --fuse, the ONLY variant whose sentry
// serves the co-located mount's in-guest FUSE mount(2)). The variant is selected
// PER SESSION on fuse — the SAME MountConfigGuestPath signal that scopes the
// CAP_SYS_ADMIN + /dev/fuse add-back in buildHostConfig (ADR-0020). This is
// least-privilege at session granularity: a pure-exec gVisor session gets the
// plain sentry, and the wider --fuse sentry surface is confined to sessions whose
// validated MountIntent actually mounts. It never confers authority — fuse shapes
// the caller's OWN sandbox, the mount stays inert without the independently
// host-attested Storage-JWT (NFR-SEC-43), exactly as the cap-add gate already
// rules. Selecting runtime, cap, and device on one predicate keeps the three from
// ever disagreeing (no /dev/fuse on a non-fuse runtime; no fuse runtime without a
// mount-config).
func dockerRuntimeForTier(tier runtime.RuntimeTier, fuse bool) string {
	switch tier {
	case runtime.TierGvisor:
		if fuse {
			return "runsc-fuse"
		}
		return "runsc"
	default: // TierRunc (and any not-yet-mapped tier): the daemon default.
		return ""
	}
}

// needsFUSE is the single per-session predicate for the co-located mount's FUSE
// need: a storage-scoped session is exactly one whose rendered mount-config was
// staged into the guest (MountConfigGuestPath set). It is the sole gate for the
// runsc-fuse runtime variant, the CAP_SYS_ADMIN + /dev/fuse add-back, and the
// boot-child --boot-child-argv wiring — one signal, so a session can never hold
// the FUSE runtime without the device, or the device without the mount.
func needsFUSE(spec runtime.SessionSpec) bool {
	return spec.Handoff.MountConfigGuestPath != ""
}

// sessionNetwork is the SINGLE source of the docker network a session's guest
// attaches to: the shared egress network for a storage-scoped session on a
// deployment that wired one, else the per-session Internal deny-all bridge. Both
// the container's HostConfig.NetworkMode and the NetworkingConfig endpoint derive
// from THIS one function, so they can never name different networks (a mismatch is
// a "network not found" materialize failure). It takes the same egressNetwork the
// provider holds; an empty egressNetwork always yields the per-session bridge.
func sessionNetwork(spec runtime.SessionSpec, egressNetwork string) string {
	if needsFUSE(spec) && egressNetwork != "" {
		return egressNetwork
	}
	return networkName(spec.Name)
}

// Materialize creates the per-session Internal bridge, the HOST-01 container, and
// starts it as ONE coarse atomic operation. It validates the spec fail-closed
// (ErrUnsupportedSpec, zero substrate calls) and aborts a TierFirecracker
// deployment with ErrNotImplemented (zero substrate calls) BEFORE any SDK call. On
// any substrate failure after the first SDK call it rolls back the already-created
// resources container-then-network (the active-endpoints constraint) so no orphan
// survives, returning ErrMaterialize.
func (p *Provider) Materialize(ctx context.Context, spec runtime.SessionSpec) (runtime.Sandbox, error) {
	// Validate BEFORE the tier gate and BEFORE any substrate call (fail-closed).
	if err := validateSpec(spec); err != nil {
		return runtime.Sandbox{}, err
	}
	if p.tier == runtime.TierFirecracker {
		// Abort with ZERO substrate calls — no insecure fallback to a weaker tier.
		return runtime.Sandbox{}, fmt.Errorf("docker: tier firecracker: %w", runtime.ErrNotImplemented)
	}

	hostCfg, err := buildHostConfig(spec, p.tier, p.egressNetwork, p.edgeHost)
	if err != nil {
		return runtime.Sandbox{}, err
	}

	bridge := networkName(spec.Name)
	cname := containerName(spec.Name)

	// A storage-scoped session (needsFUSE) reaches the egress edge over the
	// deployment-fixed shared egress network the edge is multi-homed onto; a
	// pure-exec session stays on its own per-session deny-all Internal bridge. The
	// choice is made on the SAME needsFUSE predicate as the runtime/cap/device
	// gate, so a session's network posture can never disagree with its FUSE need.
	// The egress network is only used when the deployment actually wired one
	// (egressNetwork != ""); otherwise even a storage session falls back to the
	// per-session Internal bridge (the minimal shelf), which has no edge and so
	// cannot complete a mount — a fail-closed default, never a silent leak.
	attachNet := sessionNetwork(spec, p.egressNetwork)
	useEgressNet := attachNet != bridge

	// 1. Per-session deny-all Internal bridge — SKIPPED for a session that joins the
	//    shared egress network instead. The Internal bridge is stronger than a plain
	//    bridge: no outbound NAT, so guest-out egress is denied by default. A storage
	//    session gets its reachability from the egress network (edge only), not NAT.
	if !useEgressNet {
		if _, nerr := p.api.NetworkCreate(ctx, bridge, network.CreateOptions{
			Driver:   "bridge",
			Internal: true,
			Labels: map[string]string{
				labelManaged:      managedLabelValue,
				labelSessionName:  string(spec.Name),
				labelFilesystemID: spec.Egress.FilesystemID,
			},
		}); nerr != nil {
			// Nothing created yet — map the conflict but no rollback is needed.
			return runtime.Sandbox{}, fmt.Errorf("docker: network create %q: %w", bridge, materializeError(nerr))
		}
	}

	// 2. The HOST-01 container, attached to its network (the SAME sessionNetwork the
	//    HostConfig.NetworkMode names — one source, so they cannot disagree).
	created, cerr := p.api.ContainerCreate(ctx, buildContainerConfig(spec), hostCfg, buildNetworkingConfig(attachNet), nil, cname)
	if cerr != nil {
		// Roll back the per-session bridge if we created one (the shared egress
		// network is deploy-owned and never rolled back).
		if !useEgressNet {
			p.rollbackNetwork(ctx, bridge)
		}
		return runtime.Sandbox{}, fmt.Errorf("docker: container create %q: %w", cname, materializeError(cerr))
	}

	// 3. Start the container.
	if serr := p.api.ContainerStart(ctx, created.ID, container.StartOptions{}); serr != nil {
		// Roll back container-then-network (the active-endpoints constraint).
		p.rollbackContainer(ctx, created.ID)
		if !useEgressNet {
			p.rollbackNetwork(ctx, bridge)
		}
		return runtime.Sandbox{}, fmt.Errorf("docker: container start %q: %w", created.ID, materializeError(serr))
	}

	return runtime.Sandbox{
		Name: spec.Name,
		// RuntimeID is the DETERMINISTIC container name (containerName(spec.Name),
		// the same value cname the container was created under), NOT the daemon's
		// post-create container ID. Docker accepts a name as a handle everywhere the
		// RuntimeID is later used (teardown, killswitch, exec sock-dir derivation), and
		// the name is the ONLY identity the host can stage into container_info.json
		// BEFORE Materialize runs — so the guest's boot-bound container name, the
		// staged container_info, and the exec-JWT sub all derive from this one
		// host-chosen name. Binding the post-create ID here made those three diverge
		// (the ID cannot be pre-staged), which the guest handshake rejects as
		// "sub does not match container name".
		RuntimeID: cname,
		Egress: runtime.EgressBinding{
			Name:         spec.Name,
			FilesystemID: spec.Egress.FilesystemID,
		},
		Tier: p.tier,
	}, nil
}

// rollbackContainer force-removes a container created during a failed Materialize.
// An already-gone container (IsNotFound) is benign — the orphan we were undoing
// never landed. The error is intentionally swallowed: rollback is best-effort and
// the caller already learns the create failed via ErrMaterialize.
func (p *Provider) rollbackContainer(ctx context.Context, id string) {
	if err := p.api.ContainerRemove(ctx, id, container.RemoveOptions{Force: true}); err != nil {
		if cerrdefs.IsNotFound(err) {
			return
		}
		// Best-effort: a stranded container here is reported by the next Reconcile
		// sweep rather than failing the rollback path.
		_ = err
	}
}

// rollbackNetwork removes a bridge created during a failed Materialize. An
// already-gone network (IsNotFound) is benign. The error is swallowed for the same
// best-effort reason as rollbackContainer.
func (p *Provider) rollbackNetwork(ctx context.Context, bridge string) {
	if err := p.api.NetworkRemove(ctx, bridge); err != nil {
		if cerrdefs.IsNotFound(err) {
			return
		}
		_ = err
	}
}

// materializeError maps a substrate error from the Materialize path to a typed
// sentinel, then wraps the whole create as ErrMaterialize so the caller learns the
// create failed AND that rollback ran (no orphan survives). A conflict (a network
// with active endpoints) maps to ErrNetworkActive; a not-found maps to
// ErrNoSuchContainer; everything else is wrapped raw under ErrMaterialize.
func materializeError(err error) error {
	switch {
	case cerrdefs.IsConflict(err):
		return fmt.Errorf("%w: %w", runtime.ErrMaterialize, fmt.Errorf("%w: %w", runtime.ErrNetworkActive, err))
	case cerrdefs.IsNotFound(err):
		return fmt.Errorf("%w: %w", runtime.ErrMaterialize, fmt.Errorf("%w: %w", runtime.ErrNoSuchContainer, err))
	default:
		return fmt.Errorf("%w: %w", runtime.ErrMaterialize, err)
	}
}

// Teardown returns the Docker finalizer handle bound to this provider. The two
// canon-fixed verbs share one ordered host-driven finalizer body (see teardown.go).
func (p *Provider) Teardown() runtime.RuntimeTeardown { return &teardown{p: p} }

// Reconcile is the orphan-sweep seam. It lists containers carrying the ocu-session
// label and re-derives a Sandbox (Name, RuntimeID, EgressBinding) from the labels
// and the pure-function names, so the finalizer can reclaim each orphan bridge +
// container after a controller crash mid-Materialize. A re-derived Sandbox needs no
// provider state: teardown drives entirely off SessionName.
func (p *Provider) Reconcile(ctx context.Context) ([]runtime.Sandbox, error) {
	args := filters.NewArgs()
	args.Add("label", labelManaged+"="+managedLabelValue)

	summaries, err := p.api.ContainerList(ctx, container.ListOptions{All: true, Filters: args})
	if err != nil {
		return nil, fmt.Errorf("docker: reconcile list: %w", err)
	}

	sandboxes := make([]runtime.Sandbox, 0, len(summaries))
	for i := range summaries {
		s := summaries[i]
		name := runtime.SessionName(s.Labels[labelSessionName])
		if name == "" {
			// A managed container with no session-name label cannot be re-derived
			// to a finalizer-drivable Sandbox; skip it rather than fabricate a name.
			continue
		}
		sandboxes = append(sandboxes, runtime.Sandbox{
			Name:      name,
			RuntimeID: s.ID,
			Egress: runtime.EgressBinding{
				Name: name,
				// The revoke handle on Egress.FilesystemID is the host-derived session
				// key (== labelSessionName == row.Key), the SAME key the create-path mint
				// recorded the jti under, so a reconcile-driven force-kill addresses the
				// recorded jti exactly as lifecycle.Destroy and the kill-switch do. The
				// filesystem_id label seeds the egress SCOPE, not the revocation record
				// key — binding on it instead of the session key would silently miss the
				// recorded jti once the Revoker persists across restart (NFR-SEC-01,
				// NFR-SEC-43). Keeping both revoke-driving sites on row.Key removes that
				// landmine now, while the Revoker index is in-memory and a mismatch would
				// be masked.
				FilesystemID: string(name),
			},
			Tier: p.tier,
		})
	}
	return sandboxes, nil
}

// validateSpec runs BEFORE any substrate call and rejects a malformed production
// spec with ErrUnsupportedSpec (zero substrate calls): an unknown SchemaVersion, a
// non-32-byte Ed25519 public key, a permissive EgressPolicy (DefaultDeny false), a
// missing HOST-01 bind path, or a storage-scoped mount that arrives without its
// mount-config guest path (requirement 5 — fail-closed, never the daemon
// default). The order is fixed so a malformed-key spec and a permissive-egress spec
// reject deterministically.
func validateSpec(spec runtime.SessionSpec) error {
	if spec.SchemaVersion != runtime.SchemaV1Alpha {
		return fmt.Errorf("docker: schema version %q: %w", spec.SchemaVersion, runtime.ErrUnsupportedSpec)
	}
	if len(spec.Handoff.PublicKeyEd25519) != ed25519.PublicKeySize {
		return fmt.Errorf("docker: ed25519 public key must be %d bytes, got %d: %w",
			ed25519.PublicKeySize, len(spec.Handoff.PublicKeyEd25519), runtime.ErrUnsupportedSpec)
	}
	if !spec.Egress.DefaultDeny {
		return fmt.Errorf("docker: egress policy is not deny-default: %w", runtime.ErrUnsupportedSpec)
	}
	if spec.Handoff.ContainerInfoHostPath == "" || spec.Handoff.ContainerInfoGuestPath == "" ||
		spec.Handoff.PublicKeyHostPath == "" || spec.Handoff.PublicKeyGuestPath == "" ||
		spec.Handoff.HostSockDir == "" {
		return fmt.Errorf("docker: missing HOST-01 bind path: %w", runtime.ErrUnsupportedSpec)
	}
	// A storage-scoped mount (a MountIntent naming a filesystem/memory-store
	// scope) must arrive WITH the in-guest mount-config path. Without it the guest
	// boots with no boot-child and no mount: not fail-OPEN (no scope is granted)
	// but a fail-SILENT invariant loss — the session was admitted with a storage
	// scope it never received, and nothing downstream notices the missing mount.
	// Refuse fail-closed instead. The converse (config path set, no scoped mount)
	// stays legal: the config is what carries the scope detail.
	for _, m := range spec.Mounts {
		if (m.FilesystemID != "" || m.MemoryStoreID != "") && spec.Handoff.MountConfigGuestPath == "" {
			return fmt.Errorf("docker: storage-scoped mount without a mount-config guest path (mount-config-missing, fail-silent invariant loss): %w", runtime.ErrUnsupportedSpec)
		}
	}
	return nil
}

// buildContainerConfig is the container.Config for a HOST-01 sandbox: the image,
// empty Env (no secret rides Env — requirement 5; the Storage-JWT goes into the
// mount material, never the environment), no exposed ports, the labels the
// reconciler keys on, and the LOAD-BEARING guest entrypoint Cmd.
//
// WHY THE Cmd IS LOAD-BEARING. The production guest image declares no CMD, so the
// host driver MUST supply the guest's argv here; without it the guest hits two
// distinct failure modes, and a half-fix that escapes one falls into the other:
//
//   - listener fail-STOP: --listen-uds is the guest's required listener token. With
//     no listener flag the guest exits before binding (a crash loop). An empty Cmd is
//     exactly this case.
//   - keyless fail-OPEN: --auth-public-key turns on Session JWT signature
//     verification. If it is absent the guest runs keyless and NEVER checks the JWT
//     signature — silently disabling admission. Binding the key file :ro
//     (buildHostConfig) without naming it on the Cmd is exactly as unauthenticated as
//     not binding it. This is the latent hole behind a listener-only fix.
//
// The --auth-public-key value is the SAME spec.Handoff.PublicKeyGuestPath that is
// the bind TARGET buildHostConfig mounts the key :ro at (single source — never a
// hardcoded literal), so the path the guest is told to read the key from can never
// drift from the in-guest path the host actually mounts it at. validateSpec has
// already forced a non-empty PublicKeyGuestPath and a 32-byte key before this runs,
// so the Cmd can never carry an empty key value. The socket paths derive from the
// same guestSockDir mountpoint buildHostConfig binds RW at /run/ocu.
//
// This protects CONSTITUTION invariant V / the host-derived identity binding
// (NFR-SEC-43): a guest that never verifies the Session JWT cannot enforce the
// host-attested caller identity the JWT carries — the admission decision would be
// silently void. The argv is exec-form (no shell exists to split a joined string),
// flag and value are SEPARATE elements, and it carries NO TCP-perimeter flag
// (--addr / --block-local-connections) and NO NotImplemented flag.
func buildContainerConfig(spec runtime.SessionSpec) *container.Config {
	// Exec-form argv: separate tokens, no shell. --listen-uds is the required
	// listener (fail-STOP guard); --auth-public-key turns on JWT verification
	// (fail-OPEN guard); --control-listen-uds is the additive advisory /shutdown
	// surface (ADR-0018), NOT part of the listener ArgGroup.
	cmd := []string{
		"--listen-uds", guestSockDir + "/" + execSockName,
		"--control-listen-uds", guestSockDir + "/" + controlSockName,
		"--auth-public-key", spec.Handoff.PublicKeyGuestPath,
	}
	// A storage-scoped session (MountConfigGuestPath set) appends the managed
	// boot-child flags so the guest agent starts the co-located mount binary and
	// gates serving on its ready-file, fail-closed. The mount config path IS the
	// Handoff field (single source, same discipline as PublicKeyGuestPath), and
	// the ready-file is a fixed name inside the RW sock dir. --boot-child-argv is
	// repeated once per token; the child's own --config/--ready-file ride through
	// as VALUES (the guest declares allow_hyphen_values). A pure-exec session
	// leaves cmd byte-identical to the pre-boot-child form.
	if spec.Handoff.MountConfigGuestPath != "" {
		readyPath := guestSockDir + "/" + mountReadyName
		cmd = append(cmd,
			"--boot-child-argv", mountBinGuestPath,
			"--boot-child-argv", "--config",
			"--boot-child-argv", spec.Handoff.MountConfigGuestPath,
			"--boot-child-argv", "--ready-file",
			"--boot-child-argv", readyPath,
			"--boot-child-ready-file", readyPath,
		)
	}
	return &container.Config{
		Image: spec.Image,
		// Entrypoint is set EXPLICITLY to the guest-agent binary, never left to the
		// image metadata: the argv in Cmd is a control-owned cross-repo contract, so a
		// BYO/mis-tagged image with a drifted or empty ENTRYPOINT fails loudly at start
		// (executable not found) instead of running Cmd[0] ("--listen-uds") as the
		// program. Exec form, single element.
		Entrypoint: []string{guestAgentBinPath},
		Env:        []string{}, // EMPTY on every production path (requirement 5).
		Cmd:        cmd,
		Labels: map[string]string{
			labelManaged:      managedLabelValue,
			labelSessionName:  string(spec.Name),
			labelFilesystemID: spec.Egress.FilesystemID,
		},
	}
}

// buildNetworkingConfig attaches the container to ONLY the per-session Internal
// bridge, so there is no default-bridge fallback path with outbound NAT.
func buildNetworkingConfig(bridge string) *network.NetworkingConfig {
	return &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			bridge: {},
		},
	}
}

// buildHostConfig is the HOST-01 reference, re-homed behind the D1 seam. Every
// hardening field is set unconditionally; none is caller-overridable. The seccomp
// profile is the fail-closed embedded deny-default, never the daemon default — if
// the compacted profile is empty the build refuses with ErrSeccompProfileMissing
// rather than emit a HostConfig the daemon would fill with its own default.
//
// It is the SINGLE owner of every HostConfig field, so the deployment-wide tier is
// threaded in here (not set in the caller): the Runtime string is the ONLY field
// the tier changes — every other hardening field is byte-identical across tiers,
// so a gVisor sandbox runs the same hardened HostConfig as a runc one, differing
// only in which OCI runtime dockerd hands the create to. Without this the gVisor
// admission decision would not be enforced at the OCI layer.
func buildHostConfig(spec runtime.SessionSpec, tier runtime.RuntimeTier, egressNetwork, edgeHost string) (*container.HostConfig, error) {
	if compactSeccomp == "" {
		return nil, fmt.Errorf("docker: build host config: %w", runtime.ErrSeccompProfileMissing)
	}

	// The THREE binds: container_info.json (:ro), the 32-byte Ed25519 PUBLIC key
	// (:ro), and the host-owned 0700 sock dir mounted RW at guestSockDir (no :ro).
	// Each bind is "host-source:guest-target": the SOURCE is the per-session host
	// path the Stager actually wrote (a real path on the host — a missing source
	// would be silently auto-created as an empty dir, breaking guest boot), and the
	// TARGET is the in-guest mountpoint the guest reads from. The guest creates the
	// exec UDS inside the RW sock dir; the provider never pre-creates the socket.
	// The sock-dir target is the SAME guestSockDir const the guest's listener Cmd
	// flags derive their socket paths from (buildContainerConfig), so the bind
	// target and the --listen-uds value can never drift; likewise the public-key
	// target equals the --auth-public-key value.
	binds := []string{
		spec.Handoff.ContainerInfoHostPath + ":" + spec.Handoff.ContainerInfoGuestPath + ":ro",
		spec.Handoff.PublicKeyHostPath + ":" + spec.Handoff.PublicKeyGuestPath + ":ro",
		spec.Handoff.HostSockDir + ":" + guestSockDir,
	}

	hostCfg := &container.HostConfig{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true", "seccomp=" + compactSeccomp},
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
		Binds:          binds,
		NetworkMode:    container.NetworkMode(sessionNetwork(spec, egressNetwork)),
		Resources: container.Resources{
			// HARD CPU ceiling, never a relative weight: NanoCPUs is set,
			// CPUShares stays 0 (requirement 5 — caps not shares).
			NanoCPUs:  int64(spec.Resources.CPUCores * 1e9),
			Memory:    spec.Resources.MemoryBytes,
			PidsLimit: spec.Resources.PidsLimit,
		},
		// PortBindings deliberately nil: no host port is published; the exec
		// channel rides the UDS sock bind, not a TCP port.
	}
	// A storage-scoped session (mount config delivered) needs the minimal add-back
	// for the co-located mount's in-guest mount(2): CAP_SYS_ADMIN in the effective
	// set plus the /dev/fuse device. The add-back is SCOPED — a pure-exec session
	// gets neither, so SYS_ADMIN can never leak onto a session that does not mount.
	// The rclone VFS write-cache also needs a writable /root/.cache; the rootfs is
	// read-only, so a small tmpfs is added there for the mount to cache into.
	// cap-drop ALL stays (this is add-back over drop-all, per NFR-SEC / invariant
	// 7 "cap-drop ALL with minimal add-back"); no-new-privileges and the read-only
	// rootfs are untouched — mount(2) works under both.
	fuse := needsFUSE(spec)
	if fuse {
		hostCfg.CapAdd = []string{"SYS_ADMIN"}
		hostCfg.Devices = []container.DeviceMapping{{
			PathOnHost:        "/dev/fuse",
			PathInContainer:   "/dev/fuse",
			CgroupPermissions: "rwm",
		}}
		hostCfg.Tmpfs["/root/.cache"] = "rw,nosuid,nodev,size=64m"
		// A gVisor (runsc) guest cannot reach docker's embedded DNS resolver at
		// 127.0.0.11, so the `edge` NAME in the mount-config service_url would not
		// resolve. The deployment pins the edge's IP on the shared egress network and
		// hands it here; a static ExtraHosts entry maps `edge` to it, keeping the wire
		// service_url a NAME (TLS SAN verification stays a DNS SAN, not a brittle IP
		// SAN). Only a storage session on the egress network needs it; empty edgeHost
		// (the minimal shelf) adds nothing.
		if edgeHost != "" {
			hostCfg.ExtraHosts = append(hostCfg.ExtraHosts, "edge:"+edgeHost)
		}
	}

	// The isolation tier plus the per-session FUSE need select the OCI runtime
	// dockerd uses: "runsc-fuse" for a gVisor session that mounts, "runsc" for a
	// plain gVisor session, "" (the daemon default) under runc. This is the only
	// tier-dependent field; everything above is identical across tiers. An empty
	// string omits the field (json:",omitempty"), so dockerd applies its default
	// runtime for TierRunc — confirming empty is the correct runc value. fuse is
	// the SAME predicate that scoped the cap/device add-back above, so a session's
	// runtime and its capabilities can never disagree.
	hostCfg.Runtime = dockerRuntimeForTier(tier, fuse)
	return hostCfg, nil
}

// asTeardownError joins the non-not-found substrate failures collected across a
// finalizer run under ErrTeardown, or returns nil when every step that ran either
// succeeded or was idempotently already-satisfied. It is in this file (not
// teardown.go) only to keep the errors import local to one place; the finalizer
// body in teardown.go calls it once at the end.
func asTeardownError(steps []error) error {
	joined := errors.Join(steps...)
	if joined == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", runtime.ErrTeardown, joined)
}
