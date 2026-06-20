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
	// labelFilesystemID carries the egress scope so the re-derived EgressBinding
	// is complete enough to drive the finalizer's route drop.
	labelFilesystemID = "ocu-filesystem-id"
)

// managedLabelValue is the constant value of labelManaged; the reconciler's list
// filter keys on the (key, value) pair.
const managedLabelValue = "true"

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
type Revoker interface {
	Revoke(ctx context.Context, bind runtime.EgressBinding) error
}

// Provider is the Docker RuntimeProvider. It holds the SDK behind the dockerAPI
// seam and the deployment-wide isolation tier it was constructed bound to (the
// tier is not per-request — requirement 5). It owns NO session state; teardown
// re-derives every resource name purely from the Sandbox's SessionName.
type Provider struct {
	api     dockerAPI
	tier    runtime.RuntimeTier
	revoker Revoker
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
	return &Provider{api: api, tier: tier, revoker: deps.Revoker}, nil
}

// networkName is the pure function from session name to per-session bridge name,
// so teardown and Reconcile derive the same name without a lookup (requirement 5,
// NFR-SEC-43).
func networkName(name runtime.SessionName) string { return "ocu-net-" + string(name) }

// containerName is the pure function from session name to container name.
func containerName(name runtime.SessionName) string { return "ocu-sess-" + string(name) }

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

	hostCfg, err := buildHostConfig(spec)
	if err != nil {
		return runtime.Sandbox{}, err
	}

	bridge := networkName(spec.Name)
	cname := containerName(spec.Name)

	// 1. Per-session deny-all Internal bridge (stronger than a plain bridge: no
	//    outbound NAT, so guest-out egress is denied by default).
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

	// 2. The HOST-01 container, attached to the per-session bridge.
	created, cerr := p.api.ContainerCreate(ctx, buildContainerConfig(spec), hostCfg, buildNetworkingConfig(bridge), nil, cname)
	if cerr != nil {
		// Roll back the bridge (no container exists to remove first).
		p.rollbackNetwork(ctx, bridge)
		return runtime.Sandbox{}, fmt.Errorf("docker: container create %q: %w", cname, materializeError(cerr))
	}

	// 3. Start the container.
	if serr := p.api.ContainerStart(ctx, created.ID, container.StartOptions{}); serr != nil {
		// Roll back container-then-network (the active-endpoints constraint).
		p.rollbackContainer(ctx, created.ID)
		p.rollbackNetwork(ctx, bridge)
		return runtime.Sandbox{}, fmt.Errorf("docker: container start %q: %w", created.ID, materializeError(serr))
	}

	return runtime.Sandbox{
		Name:      spec.Name,
		RuntimeID: created.ID,
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
				Name:         name,
				FilesystemID: s.Labels[labelFilesystemID],
			},
			Tier: p.tier,
		})
	}
	return sandboxes, nil
}

// validateSpec runs BEFORE any substrate call and rejects a malformed production
// spec with ErrUnsupportedSpec (zero substrate calls): an unknown SchemaVersion, a
// non-32-byte Ed25519 public key, a permissive EgressPolicy (DefaultDeny false), or
// a missing HOST-01 bind path (requirement 5 — fail-closed, never the daemon
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
	if spec.Handoff.ContainerInfoPath == "" || spec.Handoff.PublicKeyPath == "" || spec.Handoff.HostSockDir == "" {
		return fmt.Errorf("docker: missing HOST-01 bind path: %w", runtime.ErrUnsupportedSpec)
	}
	return nil
}

// buildContainerConfig is the container.Config for a HOST-01 sandbox: the image,
// empty Env (no secret rides Env — requirement 5; the Storage-JWT goes into the
// mount material, never the environment), no exposed ports, and the labels the
// reconciler keys on. The mount AuthToken is deliberately absent from Env.
func buildContainerConfig(spec runtime.SessionSpec) *container.Config {
	return &container.Config{
		Image: spec.Image,
		Env:   []string{}, // EMPTY on every production path (requirement 5).
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
func buildHostConfig(spec runtime.SessionSpec) (*container.HostConfig, error) {
	if compactSeccomp == "" {
		return nil, fmt.Errorf("docker: build host config: %w", runtime.ErrSeccompProfileMissing)
	}

	// The THREE binds: container_info.json (:ro), the 32-byte Ed25519 PUBLIC key
	// (:ro), and the host-owned 0700 sock dir mounted RW at /run/ocu (no :ro). The
	// guest creates the exec UDS inside the RW dir; the provider never pre-creates
	// the socket.
	binds := []string{
		spec.Handoff.ContainerInfoPath + ":" + spec.Handoff.ContainerInfoPath + ":ro",
		spec.Handoff.PublicKeyPath + ":" + spec.Handoff.PublicKeyPath + ":ro",
		spec.Handoff.HostSockDir + ":/run/ocu",
	}

	hostCfg := &container.HostConfig{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true", "seccomp=" + compactSeccomp},
		ReadonlyRootfs: true,
		Tmpfs:          map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
		Binds:          binds,
		NetworkMode:    container.NetworkMode(networkName(spec.Name)),
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
