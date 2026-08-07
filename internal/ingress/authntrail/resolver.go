// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package authntrail decorates an ingress.IdentityResolver with the OCSF 3002
// authentication trail (#107): one logon per accepted connection, every
// failure, fail-open with counted loss.
//
// A decorator, not resolver or handler code, because the resolvers' contract
// is "performs no I/O" and their purity is what their unit tests stand on,
// while the handlers are many and any of them could forget. The decorator sees
// exactly what a 3002 record needs — the connection's credential material and
// the resolution outcome — and nothing it lacks; the route belongs to the
// action's own record, not the logon.
package authntrail

import (
	"context"
	"sync/atomic"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// Emit lands one authentication record on the audit spine. It is the seam the
// daemon fills with ChainSink.EmitAuthn; tests fill it with a collector.
type Emit func(ctx context.Context, rec ocsf.AuthnRecord) error

// Resolver wraps an inner IdentityResolver with the authentication trail.
type Resolver struct {
	inner ingress.IdentityResolver
	emit  Emit
	// dropped counts logon records the emit refused (NFR-SEC-79: a downstream
	// failure neither blocks nor denies; a loss is counted, never silent).
	dropped atomic.Int64
}

// Wrap decorates inner. A nil emit would be a trail that silently observes
// nothing, so it panics at construction — the one place a miswire is louder
// than at every request.
func Wrap(inner ingress.IdentityResolver, emit Emit) *Resolver {
	if inner == nil || emit == nil {
		panic("authntrail: nil resolver or emit")
	}
	return &Resolver{inner: inner, emit: emit}
}

// Dropped is how many records the emit refused since construction. The ops
// surface exposes it so a counted loss is an alarm, not a log line nobody
// reads.
func (r *Resolver) Dropped() int64 { return r.dropped.Load() }

// Resolve resolves through the inner resolver and records the act.
//
// Successes are latched per connection: the TLS handshake or SO_PEERCRED
// attestation is the authentication act, and every request on the connection
// re-reads that same attestation — a per-request event would fabricate
// authentications that never happened. Failures always emit; there is no such
// thing as a repeated failure that stops mattering.
//
// The emit is fail-open both ways. A failed success-record must not take the
// plane down when the disk is full — the fail-closed anchor is downstream, on
// the privileged actions themselves — and a failed failure-record guards a
// request that was already being denied. The loss is counted either way, and a
// failed emit does NOT latch: the next request retries the logon the trail is
// missing.
func (r *Resolver) Resolve(ctx context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	caller, err := r.inner.Resolve(ctx, conn)
	if err != nil {
		rec := recordFor(conn)
		rec.Outcome = ocsf.AuthnFailure
		rec.FailureDetail = err.Error()
		if emitErr := r.emit(ctx, rec); emitErr != nil {
			r.dropped.Add(1)
		}
		return ingress.AuthenticatedCaller{}, err
	}

	latch := ingress.AuthnLatchFrom(ctx)
	if latch == nil || latch.CompareAndSwap(false, true) {
		rec := recordFor(conn)
		rec.Outcome = ocsf.AuthnSuccess
		rec.Caller = caller.Identity.Caller
		rec.Tenant = caller.Identity.Tenant
		if emitErr := r.emit(ctx, rec); emitErr != nil {
			r.dropped.Add(1)
			if latch != nil {
				// The trail does not hold this logon; let the next request on the
				// connection try again rather than treating the loss as recorded.
				latch.Store(false)
			}
		}
	}
	return caller, nil
}

// recordFor maps the connection's credential material onto the record: SANs
// mean mTLS, a PeerCred means the operator socket. A socket peer must not
// invent a certificate.
func recordFor(conn ingress.ConnInfo) ocsf.AuthnRecord {
	rec := ocsf.AuthnRecord{
		Activity: ocsf.AuthnLogon,
		Channel:  conn.Channel.String(),
		ConnID:   conn.ConnID,
	}
	switch {
	case len(conn.CertSANs) > 0:
		rec.Protocol = ocsf.AuthnProtocolMTLS
		rec.CertSAN = conn.CertSANs[0]
	case conn.PeerCred != nil:
		rec.Protocol = ocsf.AuthnProtocolPeerCred
	default:
		// Unattested: no credential material at all. The protocol stays the
		// channel's own, and resolution will have refused already.
		if conn.Channel == ingress.ChannelOperator {
			rec.Protocol = ocsf.AuthnProtocolPeerCred
		} else {
			rec.Protocol = ocsf.AuthnProtocolMTLS
		}
	}
	return rec
}
