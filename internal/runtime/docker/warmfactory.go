// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package docker

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/runtime/warmpool"
)

// WarmFactory is the docker warmpool.Factory: it creates never-started
// placeholder containers off the session-create path and, at claim, specializes
// their handoff in place, attaches a fresh per-session bridge, renames, and
// starts them. It shares the SAME hardened container/host config builders the
// cold Materialize path uses, so a warm-hit session is byte-identical to a cold
// one except for WHEN the expensive create happened.
//
// Network split (the ruled design): a placeholder is created with NO network
// (NetworkMode "none"), because docker bakes the network name at create and
// cannot rename it, and teardown re-derives the per-session bridge purely from
// the final session name. At claim the real per-session bridge ocu-net-<key> is
// created and the container connected to it BEFORE start.
type WarmFactory struct {
	api           dockerAPI
	stager        handoff.Stager
	tier          runtime.RuntimeTier
	egressNetwork string
	edgeHost      string
	seq           atomic.Int64
}

var _ warmpool.Factory = (*WarmFactory)(nil)

// NewWarmFactory builds the docker warm factory bound to the deployment-wide
// tier and egress wiring (the SAME values the Provider holds) plus the Stager
// that stages a placeholder handoff at create and specializes it at claim.
func NewWarmFactory(api dockerAPI, stager handoff.Stager, tier runtime.RuntimeTier, egressNetwork, edgeHost string) *WarmFactory {
	return &WarmFactory{api: api, stager: stager, tier: tier, egressNetwork: egressNetwork, edgeHost: edgeHost}
}

// placeholderName derives a unique, teardown-irrelevant name for a pooled unit.
// It is NEVER the session name (assigned at claim by ContainerRename); it only
// has to be unique among live placeholders, so it carries a per-factory sequence.
func placeholderName(seq int64) string { return "ocu-pool-" + strconv.FormatInt(seq, 10) }

// CreatePlaceholder stages a placeholder handoff, then creates a never-started
// container for the profile under the placeholder name with NO network. It
// issues exactly StagePlaceholder + ContainerCreate — never ContainerStart, so
// the unit is a never-run guest (NFR-SEC-68) carrying no tenant data
// (NFR-SEC-70; the handoff is a non-tenant placeholder until claim).
func (f *WarmFactory) CreatePlaceholder(ctx context.Context, p warmpool.Profile) (warmpool.Unit, error) {
	if f.tier == runtime.TierFirecracker {
		return warmpool.Unit{}, fmt.Errorf("docker warm: tier firecracker: %w", runtime.ErrNotImplemented)
	}
	name := runtime.SessionName(placeholderName(f.seq.Add(1)))

	staged, err := f.stager.StagePlaceholder(ctx, name)
	if err != nil {
		return warmpool.Unit{}, fmt.Errorf("docker warm: stage placeholder: %w", err)
	}
	spec := placeholderSpec(p, name, staged.Material)

	hostCfg, herr := buildHostConfig(spec, f.tier, f.egressNetwork, f.edgeHost)
	if herr != nil {
		_ = f.stager.Unstage(context.WithoutCancel(ctx), staged)
		return warmpool.Unit{}, herr
	}
	// No network at create: override the session-derived NetworkMode with "none"
	// so the placeholder holds no bridge to leak and teardown never looks for one
	// under the placeholder name. The real bridge is attached at claim.
	hostCfg.NetworkMode = container.NetworkMode("none")

	created, cerr := f.api.ContainerCreate(ctx, buildContainerConfig(spec), hostCfg, nil, nil, string(name))
	if cerr != nil {
		_ = f.stager.Unstage(context.WithoutCancel(ctx), staged)
		return warmpool.Unit{}, fmt.Errorf("docker warm: create placeholder %q: %w", name, materializeError(cerr))
	}
	return warmpool.Unit{PlaceholderID: created.ID, Profile: p, Handoff: staged}, nil
}

// DestroyPlaceholder force-removes an unclaimed placeholder and unstages its
// handoff root (the reaper / shutdown path). A placeholder has no network, so
// there is no bridge to remove; the container remove is idempotent (a not-found
// is a satisfied destroy).
func (f *WarmFactory) DestroyPlaceholder(ctx context.Context, u warmpool.Unit) error {
	if err := f.api.ContainerRemove(ctx, u.PlaceholderID, container.RemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("docker warm: destroy placeholder %s: %w", u.PlaceholderID, err)
	}
	if staged, ok := u.Handoff.(handoff.Staged); ok {
		_ = f.stager.Unstage(ctx, staged)
	}
	return nil
}

// Claim converts a pooled placeholder into a live session, in the ONLY order the
// guest contract permits — every specialize step runs BEFORE the guest boots:
//
//  1. ClaimSpecialize: overwrite the placeholder container_info + public key IN
//     PLACE (same inode) with the session's real host-attested identity, so the
//     guest binds the real identity at first boot (NFR-SEC-69).
//  2. ContainerRename: placeholder -> ocu-sess-<key>, the name teardown and the
//     exec-JWT sub both re-derive.
//  3. NetworkCreate the per-session deny-all bridge ocu-net-<key> (or, for a
//     storage/FUSE profile on a deployment with a shared egress network, reuse
//     that) and NetworkConnect the container to it — each claimed unit gets its
//     own isolated network exactly like a cold create.
//  4. ContainerStart: the guest boots, reads the now-real container_info, and
//     serves under its real identity.
//
// On any step failure it rolls back what it created (disconnect+remove the
// bridge; the rename is harmless — teardown addresses the container by id) and
// returns ErrMaterialize, leaving no orphan. It returns the live Sandbox handle
// and the specialized HandoffMaterial for the session row.
func (f *WarmFactory) Claim(ctx context.Context, u warmpool.Unit, realName runtime.SessionName, realPubKey []byte, egress runtime.EgressPolicy) (runtime.Sandbox, runtime.HandoffMaterial, error) {
	staged, ok := u.Handoff.(handoff.Staged)
	if !ok {
		return runtime.Sandbox{}, runtime.HandoffMaterial{}, fmt.Errorf("docker warm: claim on a unit with no staged handoff: %w", runtime.ErrMaterialize)
	}

	// 1. Specialize the handoff in place (before the guest boots).
	mat, serr := f.stager.ClaimSpecialize(ctx, staged, realName, realPubKey)
	if serr != nil {
		return runtime.Sandbox{}, runtime.HandoffMaterial{}, fmt.Errorf("docker warm: claim specialize: %w", serr)
	}

	// 2. Rename the placeholder container to its final per-session name.
	cname := containerName(realName)
	if rerr := f.api.ContainerRename(ctx, u.PlaceholderID, cname); rerr != nil {
		return runtime.Sandbox{}, runtime.HandoffMaterial{}, fmt.Errorf("docker warm: rename %q: %w", cname, materializeError(rerr))
	}

	// 3. Attach a fresh per-session network. A storage/FUSE profile on a
	//    deployment with a shared egress network joins that; otherwise a new
	//    per-session deny-all Internal bridge — the SAME sessionNetwork predicate
	//    the cold path uses, keyed on the profile's FUSE posture.
	bridge := networkName(realName)
	attachNet := sessionNetwork(specForNetwork(u.Profile, realName, egress), f.egressNetwork)
	createdBridge := false
	if attachNet == bridge {
		if _, nerr := f.api.NetworkCreate(ctx, bridge, network.CreateOptions{
			Driver:   "bridge",
			Internal: true,
			Labels: map[string]string{
				labelManaged:      managedLabelValue,
				labelSessionName:  string(realName),
				labelFilesystemID: egress.FilesystemID,
			},
		}); nerr != nil {
			return runtime.Sandbox{}, runtime.HandoffMaterial{}, fmt.Errorf("docker warm: create bridge %q: %w", bridge, materializeError(nerr))
		}
		createdBridge = true
	}
	if cerr := f.api.NetworkConnect(ctx, attachNet, cname, nil); cerr != nil {
		if createdBridge {
			f.rollbackClaimBridge(ctx, bridge)
		}
		return runtime.Sandbox{}, runtime.HandoffMaterial{}, fmt.Errorf("docker warm: connect %q to %q: %w", cname, attachNet, materializeError(cerr))
	}

	// 4. Start the guest — it boots into its real identity.
	if serr := f.api.ContainerStart(ctx, cname, container.StartOptions{}); serr != nil {
		if createdBridge {
			_ = f.api.NetworkRemove(context.WithoutCancel(ctx), bridge)
		}
		return runtime.Sandbox{}, runtime.HandoffMaterial{}, fmt.Errorf("docker warm: start %q: %w", cname, materializeError(serr))
	}

	return runtime.Sandbox{
		Name:      realName,
		RuntimeID: cname,
		Egress:    runtime.EgressBinding{Name: realName, FilesystemID: egress.FilesystemID},
		Tier:      f.tier,
	}, mat, nil
}

// rollbackClaimBridge best-effort removes a per-session bridge created during a
// failed claim, so a NetworkConnect failure leaves no orphan bridge.
func (f *WarmFactory) rollbackClaimBridge(ctx context.Context, bridge string) {
	_ = f.api.NetworkRemove(context.WithoutCancel(ctx), bridge)
}

// specForNetwork builds the minimal SessionSpec sessionNetwork() needs to pick
// the claim-time network: the real name (for the per-session bridge name) and
// the FUSE posture (from the profile) so a storage claim joins the egress
// network and a pure-exec claim gets its own bridge, matching the cold path.
func specForNetwork(p warmpool.Profile, name runtime.SessionName, egress runtime.EgressPolicy) runtime.SessionSpec {
	spec := runtime.SessionSpec{Name: name, Egress: egress}
	if p.FUSE {
		spec.Handoff.MountConfigGuestPath = guestSockDir + "/mount-config.json"
	}
	return spec
}

// placeholderSpec builds a substrate-neutral SessionSpec for a pooled unit out
// of its Profile and the placeholder handoff material. It carries the profile's
// image, hard caps, and FUSE posture (baked at create) plus the placeholder
// handoff; the container's argv references the FIXED guest paths (public key,
// mount-config), which are profile-stable — only the file CONTENT is specialized
// at claim.
func placeholderSpec(p warmpool.Profile, name runtime.SessionName, mat runtime.HandoffMaterial) runtime.SessionSpec {
	pids := p.PidsLimit
	spec := runtime.SessionSpec{
		SchemaVersion: runtime.SchemaV1Alpha,
		Name:          name,
		Image:         p.ImageRef,
		Egress:        runtime.EgressPolicy{DefaultDeny: true},
		Resources:     runtime.ResourceCaps{CPUCores: p.CPUCores, MemoryBytes: p.MemoryBytes, PidsLimit: &pids},
		Handoff:       mat,
	}
	if p.FUSE {
		// A storage-profile placeholder bakes the boot-child argv (the SAME argv a
		// cold storage session gets); the mount-config CONTENT is tenant-specific
		// and written at claim, only its fixed guest PATH is baked here.
		spec.Handoff.MountConfigGuestPath = guestSockDir + "/mount-config.json"
	}
	return spec
}
