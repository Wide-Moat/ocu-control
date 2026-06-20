// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ErrPeerCredUnavailable is the fail-closed cause the build-tagged peercred path
// returns when no kernel-vouched peer credential is readable: a non-Unix conn, a
// getsockopt failure, or any non-Linux build (where SO_PEERCRED does not exist).
// The resolver wraps it under ingress.ErrUnattested so a caller above branches on
// the shared unattested sentinel while the cause stays diagnosable. Callers match
// it with errors.Is.
var ErrPeerCredUnavailable = errors.New("operator: peer credentials unavailable (fail-closed)")

// PeerCredResolver derives the host-attested caller of an operator Unix-socket
// connection from SO_PEERCRED. It is the operator ingress's concrete
// ingress.IdentityResolver: the kernel-vouched uid/gid/pid is the ONLY identity
// source — a request body is never consulted (NFR-SEC-43). It fails closed
// (ingress.ErrUnattested) whenever the kernel attests nothing, so an unattested
// connection is refused BEFORE any handler runs and before any host state is
// touched.
//
// The mapping from a uid to a state.Identity is deliberately deterministic and
// host-derived: the Tenant and Caller are computed from the kernel-reported uid,
// never from anything the peer sends. A deployment that maps specific uids to
// named operator principals supplies a UIDMapper; the default maps every attested
// uid into a single host-scoped operator tenant keyed by the numeric uid, which is
// still entirely host-derived.
type PeerCredResolver struct {
	// mapUID turns a kernel-attested PeerCred into the host-derived identity the
	// session registry keys on. It never sees a request body. A nil mapper uses
	// defaultUIDMap.
	mapUID UIDMapper
}

// UIDMapper maps a kernel-attested peer credential to the host-derived identity
// the control plane acts on. It is the deployment's hook for naming operator
// principals from uids; it receives ONLY the kernel-vouched PeerCred, so it can
// never derive identity from a request body. Returning an error refuses the
// connection fail-closed (e.g. a uid not on the operator allowlist).
type UIDMapper func(cred ingress.PeerCred) (state.Identity, error)

// operatorTenant is the host-scoped tenant every operator-socket caller is billed
// and audited under by the default mapper. The operator ingress is the privileged
// lifecycle plane; its callers are host operators, not gateway tenants, so they
// share one host-derived tenant and are distinguished by their uid-derived caller
// principal.
const operatorTenant = "ocu-operator"

// defaultUIDMap is the host-derived identity mapping used when no UIDMapper is
// supplied: the tenant is the fixed operator tenant and the caller principal is
// the numeric uid the kernel attested. Both are host-derived — the peer supplies
// nothing — so the binding is the runtime-attested caller identity, never a hint.
func defaultUIDMap(cred ingress.PeerCred) (state.Identity, error) {
	return state.Identity{
		Tenant: operatorTenant,
		Caller: "uid:" + strconv.FormatUint(uint64(cred.UID), 10),
	}, nil
}

// NewPeerCredResolver constructs the operator resolver. A nil mapper selects the
// default host-derived uid mapping; a deployment passes its own to name operator
// principals or enforce a uid allowlist.
func NewPeerCredResolver(mapper UIDMapper) *PeerCredResolver {
	if mapper == nil {
		mapper = defaultUIDMap
	}
	return &PeerCredResolver{mapUID: mapper}
}

var _ ingress.IdentityResolver = (*PeerCredResolver)(nil)

// Resolve derives the host-attested caller from conn's PeerCred. It requires the
// operator channel and a populated PeerCred (the listener fills it from
// peerCredOf before dispatch); a missing or empty credential, or any mapper
// refusal, yields ingress.ErrUnattested with the cause wrapped. It consults no
// request body. The context is first per repo convention; this resolver performs
// no I/O of its own (the getsockopt already ran at accept time).
func (r *PeerCredResolver) Resolve(_ context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	if conn.Channel != ingress.ChannelOperator {
		return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: operator resolver on non-operator channel %s", ingress.ErrUnattested, conn.Channel)
	}
	if conn.PeerCred == nil {
		// No kernel-vouched credential: fail closed, never a body fallback.
		return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: no peer credentials on the connection", ingress.ErrUnattested)
	}
	id, err := r.mapUID(*conn.PeerCred)
	if err != nil {
		return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: map peer uid: %w", ingress.ErrUnattested, err)
	}
	if id.Tenant == "" || id.Caller == "" {
		// A mapper that produced an empty identity is treated as unattested: an empty
		// identity must never seed a Key or touch host state.
		return ingress.AuthenticatedCaller{}, fmt.Errorf("%w: peer uid mapped to an empty identity", ingress.ErrUnattested)
	}
	return ingress.AuthenticatedCaller{
		Identity: id,
		Channel:  ingress.ChannelOperator,
	}, nil
}

// connCredOf reads the kernel-attested PeerCred of an accepted operator
// connection and wraps it in a ConnInfo on the operator channel. It is the bridge
// between the raw net.Conn the listener accepted and the transport-neutral
// ConnInfo the resolver inspects, so the resolver itself never touches a socket.
// A peerCredOf failure (including every non-Linux build) propagates wrapped, and
// the listener refuses the connection fail-closed.
func connCredOf(conn net.Conn) (ingress.ConnInfo, error) {
	cred, err := peerCredOf(conn)
	if err != nil {
		return ingress.ConnInfo{}, err
	}
	return ingress.ConnInfo{
		Channel:  ingress.ChannelOperator,
		PeerCred: &cred,
	}, nil
}
