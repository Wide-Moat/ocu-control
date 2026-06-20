// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ingress is the shared seam both listeners stand on: the type-level
// scope separation between the operator/lifecycle ingress and the gateway
// service-identity ingress (NFR-SEC-52), the host-derived identity port both
// listeners resolve a caller through (NFR-SEC-43), and the small transport-
// neutral value types (AuthenticatedCaller, ConnInfo, PeerCred, Channel) that
// flow from a resolver into the lifecycle Manager. The two concrete listeners
// and their concrete resolvers live in the operator and gateway sub-packages;
// this package holds only what both share, and it imports internal/state for the
// host-derived Identity and nothing else.
//
// The load-bearing invariant is capability-by-possession. The kill-switch,
// denylist edit, quota override, and force-kill destroy are reachable ONLY with
// an OperatorScope, and an OperatorScope is mintable ONLY by a holder of an
// OperatorSeam value. The cmd wiring constructs exactly ONE OperatorSeam
// (NewOperatorSeam) and hands it to exactly ONE adapter (the operator listener);
// the gateway adapter is given no seam. Because the witness an OperatorScope
// wraps is an unexported zero-value type that cannot be named or composite-
// littered outside this package, no code outside here can forge an OperatorScope,
// and no code without a seam can mint one. A gateway call to an operator-only
// method therefore does not COMPILE — the scope separation is a compile fact, not
// a runtime route check. A compile-fail fixture and an import-graph test make
// this load-bearing; the deploy-time endpoint split (Unix socket vs TCP) and a CI
// rendered-manifest deny check are defense-in-depth on top, not the primary
// enforcement.
package ingress

import (
	"context"
	"errors"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// operatorWitness and serviceWitness are the two UNEXPORTED witness types the two
// scopes wrap. They are un-nameable and un-composite-litterable outside this
// package (their identifiers are unexported), so the only witness any other package
// can ever observe is the one this package seals into a scope. The two scopes wrap
// DISTINCT concrete pointer types (not a shared interface): that distinction is
// what makes OperatorScope and ServiceScope NON-CONVERTIBLE to each other. Go's
// struct-conversion rule (identical field names and types) would otherwise let a
// foreign package write OperatorScope(serviceScopeValue) and cross the seal at
// compile time; with different field types the conversion does not compile.
type operatorWitness struct{}

type serviceWitness struct{}

// genuineOperatorWitness is the single sealed *operatorWitness NewOperatorSeam
// stamps into the one true seam. A scope carrying this exact pointer (propagated
// through Mint) is the only OperatorScope that passes Valid. It is package-private
// and escapes only inside an OperatorScope, where it is opaque.
var genuineOperatorWitness = &operatorWitness{}

// genuineServiceWitness is the sealed *serviceWitness ServiceScopeFor stamps into a
// service scope, the symmetric backstop for ServiceScope.Valid.
var genuineServiceWitness = &serviceWitness{}

// OperatorScope is the capability the operator ingress holds. Operator-only methods
// (kill-switch RevokeOne/RevokeAll, denylist edit, quota override, force-kill
// destroy) take it as a REQUIRED parameter, so a gateway caller — which can obtain
// no value of it — cannot even FORM a call to them. Its single field is UNEXPORTED
// and a concrete *operatorWitness, so no package outside this one can build a
// non-zero OperatorScope with a composite literal NOR convert a ServiceScope into
// one; the only producer is OperatorSeam.Mint. The zero value is inert: Valid
// reports false for it, and every operator-only method asserts Valid before acting,
// so a zero-value OperatorScope passed by reflection or an accidental struct copy
// authorizes nothing.
type OperatorScope struct {
	w *operatorWitness
}

// Valid reports whether s is a genuine minted OperatorScope rather than the inert
// zero value or one minted from a forged zero-value seam. It holds ONLY when the
// wrapped witness is the single sealed genuineOperatorWitness pointer, which is
// reachable solely through a seam NewOperatorSeam produced. A zero-value
// OperatorScope (nil witness) and a scope minted from a zero-value OperatorSeam
// (nil witness) both fail here. Operator-only methods call Valid before acting as
// the runtime backstop to the compile-time seal.
func (s OperatorScope) Valid() bool {
	return s.w == genuineOperatorWitness
}

// ServiceScope is the capability the gateway ingress holds. Service methods
// (Create, Destroy, Status) take it. There is NO conversion ServiceScope →
// OperatorScope: the two wrap distinct unexported pointer types, so the struct
// conversion does not compile, and this package exposes no function that widens one
// to the other. Its single field is UNEXPORTED, so the only producer is
// ServiceScopeFor.
type ServiceScope struct {
	w *serviceWitness
}

// Valid reports whether s is a genuine minted ServiceScope rather than the inert
// zero value, the symmetric backstop to OperatorScope.Valid: it holds only for the
// single sealed genuineServiceWitness pointer ServiceScopeFor stamps.
func (s ServiceScope) Valid() bool {
	return s.w == genuineServiceWitness
}

// OperatorSeam is the single capability the cmd hands to EXACTLY ONE adapter:
// capability-by-possession, not package-import membership. Only a holder of an
// OperatorSeam can mint a VALID OperatorScope. cmd constructs ONE OperatorSeam with
// NewOperatorSeam and passes it to the operator listener alone; the gateway
// listener is given no seam value and has no import path that names this type, so a
// gateway call to an operator-only method does not COMPILE. Its single field is
// UNEXPORTED, so no foreign package can set it. Go does permit a foreign package to
// write the empty literal OperatorSeam{} (the zero value of any struct), but that
// seam's mint pointer is nil, so Mint on it produces an INVALID scope that
// OperatorScope.Valid rejects — the empty-literal hole is closed at the witness, not
// merely at the literal. An import-graph test and a compile-fail fixture keep the
// seal load-bearing.
type OperatorSeam struct {
	mint *operatorWitness
}

// NewOperatorSeam mints the single operator seam, stamping it with the sealed
// genuine witness pointer. The cmd wiring calls it once and hands the result to the
// operator adapter alone; no other call site exists.
func NewOperatorSeam() OperatorSeam {
	return OperatorSeam{mint: genuineOperatorWitness}
}

// Mint produces an OperatorScope from the seam's witness. Minting requires
// POSSESSING an OperatorSeam (it is a method on the seam value), so the capability
// is strictly by-possession: a package that holds no seam has no way to obtain a
// scope, and the seam type is the gateway's compile barrier. A genuine seam carries
// the sealed witness, so the minted scope passes Valid; a forged zero-value seam
// carries a nil witness, so the minted scope fails Valid (defense in depth behind
// the compile barrier).
func (s OperatorSeam) Mint() OperatorScope {
	return OperatorScope{w: s.mint}
}

// ServiceScopeFor mints a ServiceScope stamped with the sealed service witness. No
// seam is required: the gateway transport already proves SERVICE identity through
// the verified mTLS client-cert SAN the gateway resolver derives the caller from,
// so the scope token here marks that the call arrived on the service ingress, not a
// second authority gate.
func ServiceScopeFor() ServiceScope {
	return ServiceScope{w: genuineServiceWitness}
}

// Channel records which ingress a caller arrived on, for the audit record and a
// scope sanity check. The set is closed.
type Channel uint8

const (
	// ChannelOperator is the operator/lifecycle ingress (the Unix socket): peer
	// creds attest the caller, and the kill-switch lives here.
	ChannelOperator Channel = iota
	// ChannelGateway is the gateway service-identity ingress (the TCP/mTLS port):
	// a verified client-cert SAN attests the caller, and no operator route is
	// reachable.
	ChannelGateway
)

// String renders the Channel for the audit record and diagnostics. An
// out-of-range value renders as "channel_unknown" rather than a bogus label, so a
// forgotten arm surfaces in the record instead of silently mislabelling.
func (c Channel) String() string {
	switch c {
	case ChannelOperator:
		return "operator"
	case ChannelGateway:
		return "gateway"
	default:
		return "channel_unknown"
	}
}

// AuthenticatedCaller is the host-derived identity an ingress resolved BEFORE
// dispatch. A body-supplied id NEVER populates it: the Identity here comes from
// peer creds (operator) or the verified cert SAN (gateway), and it is the ONLY
// identity the lifecycle Manager acts on (NFR-SEC-43). Channel records which
// ingress produced it.
type AuthenticatedCaller struct {
	// Identity is the host-derived caller identity (Tenant + Caller). It is the
	// authority every downstream decision keys on.
	Identity state.Identity
	// Channel is the ingress this caller arrived on, carried through to the audit
	// record.
	Channel Channel
}

// PeerCred is the kernel-vouched peer identity of a Unix-socket connection. It is
// produced ONLY by the Linux SO_PEERCRED path in the operator resolver; off Linux
// that resolver returns its unavailable sentinel and admits nothing (fail-closed),
// so a PeerCred never carries a value the kernel did not vouch for.
type PeerCred struct {
	// UID is the kernel-reported user id of the connecting peer.
	UID uint32
	// GID is the kernel-reported primary group id of the connecting peer.
	GID uint32
	// PID is the kernel-reported process id of the connecting peer.
	PID int32
}

// ConnInfo is the transport material a resolver inspects. It carries NO request
// body: a resolver derives identity only from host-attested transport facts.
// Exactly one of PeerCred / CertSANs is populated, per Channel — the operator
// resolver reads PeerCred (nil off the operator channel) and the gateway resolver
// reads the verified client-cert SANs (nil off the gateway channel).
type ConnInfo struct {
	// Channel is the ingress the connection arrived on; it selects which attested
	// field the resolver reads.
	Channel Channel
	// PeerCred is the kernel-vouched uid/gid/pid of the operator Unix-socket peer.
	// It is nil on the gateway channel.
	PeerCred *PeerCred
	// CertSANs are the verified mTLS client-cert SANs of the gateway peer. It is
	// nil on the operator channel.
	CertSANs []string
}

// ErrUnattested is the fail-closed identity refusal: a resolver could not derive a
// host-attested identity from the connection (no peer creds, no verified cert
// SAN). It is returned BEFORE any handler runs and before any host state is
// touched, so an unattested connection touches nothing. Callers match it with
// errors.Is.
var ErrUnattested = errors.New("ingress: caller identity unattested, refused (fail-closed)")

// IdentityResolver turns a transport connection into an AuthenticatedCaller using
// ONLY host-attested material. A request body is never consulted. Each ingress
// supplies its own concrete resolver — the operator a peer-cred resolver, the
// gateway a cert-SAN resolver — and both fail closed (ErrUnattested) on missing
// attestation. The context is first per repo convention; an implementation that
// performs no I/O still takes it so the seam is uniform.
type IdentityResolver interface {
	// Resolve derives the host-attested caller from conn, or returns ErrUnattested
	// (or a wrapped resolver-specific cause) when no attested identity is present.
	// It MUST NOT consult a request body.
	Resolve(ctx context.Context, conn ConnInfo) (AuthenticatedCaller, error)
}
