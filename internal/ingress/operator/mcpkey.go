// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// MCPKeyCreate is the operator handler for minting a new sk-ocu- MCP API key. The
// conn is the operator ingress connection whose caller is resolved via
// resolveCaller — an unattested connection is refused with ingress.ErrUnattested
// BEFORE any engine call, matching the other operator handlers. The OperatorScope is
// minted from the held seam once the caller is attested; a gateway-shaped caller holds
// no seam and cannot compile a call to this method or to mcpkey.Engine.Create
// (NFR-SEC-52 as a compile fact — the gateway adapter imports no OperatorSeam).
//
// tenant is the operator-supplied target tenant the new key is scoped to. This is
// legitimate operator input (Q3 of the research): the operator is choosing WHICH
// TENANT the new key serves, distinct from the NFR-SEC-43 "body-supplied id is never
// the acting authority" rule, which guards the CALLER's identity. The audit actor is
// always the host-attested operator from peer-creds, never the tenant argument.
//
// expiresAt is optional: nil means non-expiring (ADR-0027 §Storage).
//
// UNMOUNTED, deliberately. This handler is complete and tested in-process but its
// wire route is DEFERRED, not missing by accident: the mcp-key HTTP/CLI route is
// gated on the architect's canon wire-freeze (operator-REST verb + Control→gateway
// hashed-key-set contract, Q7 of the research). It is on the deferredHandlers
// allow-list, which TestDeferredHandlers_AllowListIsExact enforces — a dead-code
// pass cannot delete it, and a premature mount fails the build. It is the same
// design-fenced class as LiftDeny and OverrideQuota. Plan 08-05 mounts the route
// after the canon wire-freeze checkpoint passes.
func (h *Handlers) MCPKeyCreate(ctx context.Context, conn ingress.ConnInfo, tenant, deployment string, expiresAt *time.Time) (mcpkey.SecretKey, mcpkey.Record, error) {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return mcpkey.SecretKey{}, mcpkey.Record{}, err
	}
	// The host-attested socket peer IS the operator for the admin/CLI channel, so
	// the scope is stamped with caller.Identity — the audit actor is WHO ACTED.
	scope := h.seam.Mint(caller.Identity)
	return h.mcpKeyEngine.Create(ctx, scope, tenant, deployment, expiresAt)
}

// MCPKeyRevoke is the operator handler for revoking an existing sk-ocu- MCP API
// key by key_id. Caller attestation and scope mint mirror MCPKeyCreate exactly.
// keyID is the public handle the operator passes to "revoke --id"; reason is
// operator-supplied context for the audit trail.
//
// UNMOUNTED, deliberately. Same deferral class as MCPKeyCreate — see that method's
// doc for the rationale. Plan 08-05 mounts both mcp-key routes together at the
// wire-freeze checkpoint.
func (h *Handlers) MCPKeyRevoke(ctx context.Context, conn ingress.ConnInfo, keyID, reason string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	// The host-attested socket peer IS the operator; scope carries caller.Identity
	// as the audit actor (NFR-SEC-43).
	scope := h.seam.Mint(caller.Identity)
	return h.mcpKeyEngine.Revoke(ctx, scope, keyID, reason)
}
