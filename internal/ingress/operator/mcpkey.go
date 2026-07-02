// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"errors"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// ErrMCPKeyEngineUnset is the fail-closed refusal returned when an mcp-key
// handler is reached with no MCPKeyEngine wired (a nil Deps.MCPKeyEngine). The
// route is mounted unconditionally, so a deployment that omits the engine must
// get a clean refusal, NOT a nil-pointer panic — the handler denies the action
// before any attestation or scope mint. The transport maps it to 503.
var ErrMCPKeyEngineUnset = errors.New("operator: mcp-key engine not configured, action refused (fail-closed)")

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
// MOUNTED at POST /v1alpha/mcp-keys on the operator plane ONLY (registerRoutes) —
// never on the gateway listener (NFR-SEC-52). The route landed once the canon
// Artifact-2 hashed-key-set contract was frozen; before that it was held on the
// deferredHandlers allow-list. The occ CLI is the shipped client of this route.
func (h *Handlers) MCPKeyCreate(ctx context.Context, conn ingress.ConnInfo, tenant, deployment string, expiresAt *time.Time) (mcpkey.SecretKey, mcpkey.Record, error) {
	if h.mcpKeyEngine == nil {
		return mcpkey.SecretKey{}, mcpkey.Record{}, ErrMCPKeyEngineUnset
	}
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
// MOUNTED at POST /v1alpha/mcp-keys/revoke on the operator plane ONLY, alongside
// MCPKeyCreate — see that method's doc. The store Revoke is idempotent: revoking
// an already-revoked or absent key_id is a no-op success (no cross-tenant
// existence oracle), so this route returns 200 rather than 404 for an unknown id.
// The returned RenderOutcome carries DenyAllPending when this revoke removed the
// last active key: a full success whose boot-set cannot be published as an empty
// active set, so the route surfaces a warning to the operator (open-computer-use#332).
func (h *Handlers) MCPKeyRevoke(ctx context.Context, conn ingress.ConnInfo, keyID, reason string) (mcpkey.RenderOutcome, error) {
	if h.mcpKeyEngine == nil {
		return mcpkey.RenderOutcome{}, ErrMCPKeyEngineUnset
	}
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return mcpkey.RenderOutcome{}, err
	}
	// The host-attested socket peer IS the operator; scope carries caller.Identity
	// as the audit actor (NFR-SEC-43).
	scope := h.seam.Mint(caller.Identity)
	return h.mcpKeyEngine.Revoke(ctx, scope, keyID, reason)
}
