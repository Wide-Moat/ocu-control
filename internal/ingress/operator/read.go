// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"errors"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrSessionNotFound is returned by GetSession when no live row carries the
// requested key. The route maps it to 404. It is uniform across "released" and
// "absent" so the surface discloses no existence a forge attempt could exploit.
var ErrSessionNotFound = errors.New("operator: session not found")

// ReadHandlers is the operator-plane admin read-surface (ADR-0022). It is a
// deliberately SEPARATE type from Handlers: it holds ONLY a narrow read port and
// the two deployment-wide singletons, and it holds NEITHER the OperatorSeam nor
// the lifecycle Manager nor the kill-switch Engine. That separation is the
// structural enforcement of the read-only boundary — a read handler cannot reach
// Destroy, RevokeOne/All, the denylist, or a quota override because it does not
// hold the capability that mints an OperatorScope and does not hold the mutating
// surfaces at all. The import-boundary test asserts this; the type shape makes it
// a compile fact, mirroring how the gateway adapter carries no seam (NFR-SEC-52,
// NFR-SEC-26). These routes live on the operator plane only and are never mounted
// on the gateway listener.
type ReadHandlers struct {
	reader     SessionReader
	resolver   ingress.IdentityResolver
	deployment DeploymentInfo
}

// SessionReader is the narrow read port the admin surface consumes: the enriched
// live-session enumeration through the sole custodian. It is satisfied by
// *registry.Custodian (EnrichedLiveSessions), but the read handler depends on
// this minimal interface, not the whole Custodian, so it has NO access to any
// reservation mutator. This is the read-only seam: the only capability the admin
// surface is given is "enumerate the enriched live rows".
type SessionReader interface {
	// EnrichedLiveSessions returns every live (RESERVED or ACTIVE) row with its
	// read-surface enrichment. A transient store failure or an enumeration-
	// unsupported store returns an error the handler maps to 503.
	EnrichedLiveSessions(ctx context.Context) ([]state.EnrichedSessionRow, error)
}

// DeploymentInfo is the pair of deployment-wide singletons the read surface
// reports: the runtime tier and the runtime provider chosen once at boot, never
// per request (ADR-0003). They are plain recorded strings the dashboard renders.
type DeploymentInfo struct {
	// RuntimeTier is the deployment-declared tier (runc | gvisor | firecracker).
	RuntimeTier string
	// RuntimeProvider is the deployment-declared provider (docker | k8s).
	RuntimeProvider string
}

// NewReadHandlers builds the read surface from the narrow read port, the caller
// resolver, and the deployment singletons. It is given NO seam, Manager, or
// Engine by construction, so the read-only boundary holds structurally.
func NewReadHandlers(reader SessionReader, resolver ingress.IdentityResolver, deployment DeploymentInfo) *ReadHandlers {
	return &ReadHandlers{
		reader:     reader,
		resolver:   resolver,
		deployment: deployment,
	}
}

// attest resolves the host-attested caller from the connection so an unattested
// read is refused before any enumeration runs, exactly as a mutating operator
// call is. The read surface needs the attestation gate but none of the caller's
// authority beyond "is attested" — it enumerates the deployment-wide live set, not
// a per-caller slice (the admin operator is trusted on this plane), so the
// returned caller is checked for attestation and otherwise unused.
func (h *ReadHandlers) attest(ctx context.Context, conn ingress.ConnInfo) error {
	_, err := h.resolver.Resolve(ctx, conn)
	return err
}

// SessionView is the read-surface projection of a live session (ADR-0022 frozen
// form). state is the LOWERCASE lifecycle name; container_name, caps, and
// active_at are OMITTED (nil/empty) until they exist, so the dashboard
// distinguishes a freshly-reserved row from a fully-activated one. reserved_at is
// always present. No field is authority — every value is recorded data the
// surface renders (NFR-SEC-43).
type SessionView struct {
	Key           string     `json:"key"`
	Owner         OwnerView  `json:"owner"`
	State         string     `json:"state"`
	ContainerName string     `json:"container_name,omitempty"`
	Caps          *CapsView  `json:"caps,omitempty"`
	ReservedAt    time.Time  `json:"reserved_at"`
	ActiveAt      *time.Time `json:"active_at,omitempty"`
	// EffectiveScope is the per-chat storage scope recorded at create when the
	// deployment runs -derive-chat-scope (ADR-0030, D5): "<base>-<hex>". Nil/omitted
	// when derivation is off or the create named no storage scope. Recorded data the
	// surface renders, never authority (NFR-SEC-43).
	EffectiveScope *string `json:"effective_scope,omitempty"`
}

// OwnerView is the host-derived owner pair the surface renders. It is labelling
// material, never an addressable authority a request can forge (NFR-SEC-43).
type OwnerView struct {
	Tenant string `json:"tenant"`
	Caller string `json:"caller"`
}

// CapsView is the read projection of the recorded resource caps. pids_limit is
// omitted when unset, mirroring the nullable column.
type CapsView struct {
	CPUCores    float64 `json:"cpu_cores"`
	MemoryBytes int64   `json:"memory_bytes"`
	PidsLimit   *int64  `json:"pids_limit,omitempty"`
}

// DeploymentView is the read projection of the two deployment-wide singletons.
type DeploymentView struct {
	RuntimeTier     string `json:"runtime_tier"`
	RuntimeProvider string `json:"runtime_provider"`
}

// lowercaseState maps a SessionState to the lowercase wire name the read surface
// uses (matching SessionHandle.state on this plane). An out-of-range state maps to
// "unknown" rather than panicking, so a future state can never crash the read
// path.
func lowercaseState(s state.SessionState) string {
	switch s {
	case state.StateReserved:
		return "reserved"
	case state.StateActive:
		return "active"
	case state.StateReleased:
		return "released"
	default:
		return "unknown"
	}
}

// toSessionView projects an enriched row into the wire view. A nil caps/active-at
// stays nil/omitted; a released row carries state "released" (it appears only when
// include_released is set, which the enumeration handles upstream).
func toSessionView(row state.EnrichedSessionRow) SessionView {
	v := SessionView{
		Key:            row.Key,
		Owner:          OwnerView{Tenant: row.Owner.Tenant, Caller: row.Owner.Caller},
		State:          lowercaseState(row.State),
		ContainerName:  row.ContainerName,
		ReservedAt:     row.ReservedAt,
		ActiveAt:       row.ActiveAt,
		EffectiveScope: row.EffectiveScope,
	}
	if row.Caps != nil {
		v.Caps = &CapsView{
			CPUCores:    row.Caps.CPUCores,
			MemoryBytes: row.Caps.MemoryBytes,
			PidsLimit:   row.Caps.PidsLimit,
		}
	}
	return v
}

// deploymentView returns the deployment singletons as their wire view.
func (h *ReadHandlers) deploymentView() DeploymentView {
	return DeploymentView{
		RuntimeTier:     h.deployment.RuntimeTier,
		RuntimeProvider: h.deployment.RuntimeProvider,
	}
}

// ListSessions returns the live (RESERVED + ACTIVE) sessions as wire views, after
// attesting the caller. includeReleased is reserved for the ?include_released
// flag; the enriched enumeration is the live set only (a RELEASED tombstone is not
// live), so when includeReleased is false the result is exactly the live set. The
// flag is plumbed through for forward compatibility — the enrichment seam does not
// yet enumerate tombstones, so a true value currently returns the same live set
// and is documented as such rather than silently dropping the parameter. An
// unattested caller is refused before any enumeration; a store failure propagates
// for the route to map to 503.
func (h *ReadHandlers) ListSessions(ctx context.Context, conn ingress.ConnInfo, includeReleased bool) ([]SessionView, error) {
	if err := h.attest(ctx, conn); err != nil {
		return nil, err
	}
	rows, err := h.reader.EnrichedLiveSessions(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]SessionView, 0, len(rows))
	for _, row := range rows {
		views = append(views, toSessionView(row))
	}
	return views, nil
}

// GetSession returns one live session by its host-derived key, or
// ErrSessionNotFound if no live row carries that key. It attests the caller first.
// The lookup is over the same enriched live set as ListSessions, so a RELEASED or
// absent key is uniformly "not found" — a forge attempt cannot distinguish "exists
// but released" from "never existed" on this surface.
func (h *ReadHandlers) GetSession(ctx context.Context, conn ingress.ConnInfo, key string) (SessionView, error) {
	if err := h.attest(ctx, conn); err != nil {
		return SessionView{}, err
	}
	rows, err := h.reader.EnrichedLiveSessions(ctx)
	if err != nil {
		return SessionView{}, err
	}
	for _, row := range rows {
		if row.Key == key {
			return toSessionView(row), nil
		}
	}
	return SessionView{}, ErrSessionNotFound
}

// Deployment returns the two deployment-wide singletons after attesting the
// caller. They are read once at boot and never per request (ADR-0003).
func (h *ReadHandlers) Deployment(ctx context.Context, conn ingress.ConnInfo) (DeploymentView, error) {
	if err := h.attest(ctx, conn); err != nil {
		return DeploymentView{}, err
	}
	return h.deploymentView(), nil
}
