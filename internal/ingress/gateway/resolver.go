// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrNoVerifiedSAN is the fail-closed cause the cert-SAN resolver returns when the
// connection presents no VERIFIED client-cert SAN: an unauthenticated TCP
// connection, a handshake without a client cert, or a SAN list the resolver cannot
// map to a service identity. The resolver wraps it under ingress.ErrUnattested so a
// caller above branches on the shared unattested sentinel. Callers match it with
// errors.Is.
var ErrNoVerifiedSAN = errors.New("gateway: no verified client-cert SAN (fail-closed)")

// CertSANResolver derives the host-attested SERVICE identity of a gateway TCP/mTLS
// connection from the VERIFIED client-certificate SANs. It is the gateway
// ingress's concrete ingress.IdentityResolver: the SAN the TLS stack verified
// against the trust anchor is the ONLY identity source — a request body is never
// consulted (NFR-SEC-43). It fails closed (ingress.ErrUnattested) whenever the
// transport produced no verified SAN, so an unauthenticated connection is refused
// BEFORE any handler runs and before any host state is touched.
//
// The transport (gateway.Listener) populates ConnInfo.CertSANs ONLY from
// tls.ConnectionState.VerifiedChains — a raw, unverified SAN never reaches this
// resolver — so trusting CertSANs here is sound. The mapping from a SAN to a
// state.Identity is deterministic and host-derived: the deployment supplies a
// SANMapper (e.g. a SPIFFE-ID-to-tenant table); the default parses a
// "tenant/caller"-shaped URI SAN, all host-derived from the verified certificate.
type CertSANResolver struct {
	// mapSAN turns a verified SAN into the host-derived service identity the
	// registry keys on. It never sees a request body. A nil mapper uses
	// defaultSANMap.
	mapSAN SANMapper
}

// SANMapper maps a single verified client-cert SAN to the host-derived service
// identity the control plane acts on. It receives ONLY a SAN the TLS stack
// verified against the trust anchor, so it can never derive identity from a
// request body. Returning an error refuses the SAN; the resolver tries the next
// verified SAN and fails closed if none maps.
type SANMapper func(san string) (state.Identity, error)

// defaultSANMap is the host-derived mapping used when no SANMapper is supplied: a
// SAN of the shape "tenant/caller" (optionally with a "spiffe://trust-domain/"
// prefix the mapper strips) maps Tenant=tenant and Caller=caller. Both come from
// the verified certificate, so the binding is the runtime-attested service
// identity, never a body hint. A SAN that does not fit the shape is refused so the
// resolver fails closed rather than minting a partial identity.
func defaultSANMap(san string) (state.Identity, error) {
	s := san
	// Strip a SPIFFE scheme + trust domain prefix if present, keeping the workload
	// path that names tenant/caller. A bare "tenant/caller" SAN is accepted as-is.
	if rest, ok := strings.CutPrefix(s, "spiffe://"); ok {
		// rest is "trust-domain/tenant/caller"; drop the trust domain segment.
		if _, path, found := strings.Cut(rest, "/"); found {
			s = path
		} else {
			return state.Identity{}, fmt.Errorf("spiffe SAN %q has no workload path", san)
		}
	}
	tenant, caller, ok := strings.Cut(s, "/")
	if !ok || tenant == "" || caller == "" {
		return state.Identity{}, fmt.Errorf("SAN %q is not tenant/caller-shaped", san)
	}
	return state.Identity{Tenant: tenant, Caller: caller}, nil
}

// NewCertSANResolver constructs the gateway resolver. A nil mapper selects the
// default host-derived SAN mapping; a deployment passes its own to map its
// certificate naming scheme to tenants and callers.
func NewCertSANResolver(mapper SANMapper) *CertSANResolver {
	if mapper == nil {
		mapper = defaultSANMap
	}
	return &CertSANResolver{mapSAN: mapper}
}

var _ ingress.IdentityResolver = (*CertSANResolver)(nil)

// Resolve derives the host-attested service identity from conn's verified SANs. It
// requires the gateway channel and at least one verified SAN (the listener fills
// CertSANs only from the verified chains); no SAN, or no SAN the mapper accepts,
// yields ingress.ErrUnattested. It consults no request body. The context is first
// per repo convention; this resolver performs no I/O (the handshake already ran).
func (r *CertSANResolver) Resolve(_ context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	if conn.Channel != ingress.ChannelGateway {
		return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: gateway resolver on non-gateway channel %s", ingress.ErrUnattested, conn.Channel)
	}
	if len(conn.CertSANs) == 0 {
		// No verified SAN: fail closed, never a body fallback.
		return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: connection presented no verified client-cert SAN", ingress.ErrUnattested)
	}
	var lastErr error
	for _, san := range conn.CertSANs {
		id, err := r.mapSAN(san)
		if err != nil {
			lastErr = err
			continue
		}
		if id.Tenant == "" || id.Caller == "" {
			lastErr = fmt.Errorf("SAN %q mapped to an empty identity", san)
			continue
		}
		return ingress.AuthenticatedCaller{
			Identity: id,
			Channel:  ingress.ChannelGateway,
		}, nil
	}
	return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: no verified SAN mapped to a service identity: %w", ingress.ErrUnattested, errors.Join(ErrNoVerifiedSAN, lastErr))
}
