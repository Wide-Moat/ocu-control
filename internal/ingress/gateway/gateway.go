// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package gateway is the gateway service-identity ingress adapter: the TCP/mTLS
// listener the in-workforce services reach the control plane through. It mounts
// the SERVICE surface ONLY — Create, Destroy, Status — each gated on a
// ServiceScope, and it holds NO ingress.OperatorSeam. The kill-switch, denylist
// edit, quota override, and force-kill destroy are unreachable from here as a
// COMPILE fact: this package never imports internal/killswitch and never names the
// operator-seam mint path, so a gateway call to an operator-only method does not
// compile. The import-graph test (gateway↛operator-seam) and the compile-fail
// fixture keep that load-bearing; this package's import set is the assertion's
// subject.
//
// Host-attested identity (NFR-SEC-43). Every accepted connection's SERVICE
// identity is derived from the VERIFIED client-certificate SAN through the
// CertSANResolver — the TLS stack verifies the chain against the trust anchor, and
// a request body never populates the identity. An unauthenticated connection (no
// client cert, no verified SAN) is refused with ingress.ErrUnattested BEFORE any
// handler runs and before any host state is touched.
//
// The ServiceScope here marks that a call arrived on the service ingress; it is
// NOT a second authority gate (the verified SAN already proved service identity).
// It exists so the lifecycle service methods can take a scope parameter uniformly
// and so a future service-only method is type-distinguishable from an operator
// one. The transport is a minimal mTLS-shaped TCP listener sufficient to drive and
// test create→destroy and status; the full gateway proto/OpenAPI wire is a
// follow-up.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Deps are the collaborators the gateway adapter drives. The Manager runs the
// lifecycle create/destroy pipeline; the Custodian backs the owner-scoped Status
// read; the Resolver derives the host-attested service identity from the verified
// cert SAN; the TLSConfig, when set, is the mTLS server config the listener wraps
// the TCP socket in. NOTABLY ABSENT: there is no OperatorSeam and no killswitch
// Engine — the gateway holds neither, by construction.
type Deps struct {
	// Manager runs the lifecycle create/destroy pipeline and the owner-scoped
	// Status read (the same host-derived handle→Key derivation).
	Manager *lifecycle.Manager
	// Resolver derives the host-attested service identity from an accepted
	// connection. Defaults to NewCertSANResolver(nil) when nil.
	Resolver ingress.IdentityResolver
	// TLSConfig is the mTLS server config (RequireAndVerifyClientCert + the trust
	// anchor). When nil the listener binds a plain TCP socket whose connections
	// carry no verified SAN, so every Resolve fails closed — a clearly-stubbed,
	// fail-closed posture for a Phase-3 deployment without certificates wired.
	TLSConfig *tls.Config
}

// Handlers is the stable in-process service surface. Each method takes the
// transport-neutral ingress.ConnInfo the listener resolved (carrying the verified
// SANs) and a ServiceScope, derives the host-attested service identity, and
// performs one service operation. There is no operator method here and no path to
// mint an OperatorScope.
type Handlers struct {
	manager  *lifecycle.Manager
	resolver ingress.IdentityResolver
}

// NewHandlers builds the in-process service handler surface from Deps. A nil
// Resolver defaults to the host-derived cert-SAN resolver. It binds no socket —
// Listener does — so the handlers are unit-testable with a synthetic ConnInfo and
// no transport.
func NewHandlers(deps Deps) *Handlers {
	resolver := deps.Resolver
	if resolver == nil {
		resolver = NewCertSANResolver(nil)
	}
	return &Handlers{
		manager:  deps.Manager,
		resolver: resolver,
	}
}

// resolveCaller derives the host-attested service identity from conn through the
// gateway resolver. It is the single gate every service handler runs first: an
// unattested connection is refused with ingress.ErrUnattested before any host
// state is touched. The Channel on the returned caller is always ChannelGateway.
func (h *Handlers) resolveCaller(ctx context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	return h.resolver.Resolve(ctx, conn)
}

// Create runs the lifecycle create pipeline for a gateway service caller. The
// scope marks the service ingress; the host-derived caller (from the verified SAN)
// is the authority, and the body fields are hints carried onto the CreateInput,
// never identity. The scope parameter makes the method service-shaped uniformly;
// the verified SAN is the real gate.
func (h *Handlers) Create(ctx context.Context, _ ingress.ServiceScope, conn ingress.ConnInfo, req CreateRequest) (state.SessionRow, error) {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return state.SessionRow{}, err
	}
	in := lifecycle.CreateInput{
		Caller:      caller,
		SessionHint: req.SessionHint,
		Image:       req.Image,
		Mount:       req.Mount,
		Egress:      req.Egress,
		Resources:   req.Resources,
	}
	return h.manager.Create(ctx, in)
}

// Destroy runs the lifecycle destroy path for a gateway service caller. The
// host-derived caller gates the row lookup; a foreign sessionHint yields
// registry.ErrNotOwned (indistinguishable from not-found), never the victim's
// teardown. The scope marks the service ingress.
func (h *Handlers) Destroy(ctx context.Context, _ ingress.ServiceScope, conn ingress.ConnInfo, sessionHint string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	return h.manager.Destroy(ctx, caller, sessionHint)
}

// Status returns the caller's OWN session row addressed by sessionHint, through
// the Manager's audience-scoped status read (the SAME host-derived handle→Key
// derivation Create and Destroy use). A foreign or absent row yields
// registry.ErrNotOwned (indistinguishable from not-found), so a service caller can
// neither read another tenant's session nor probe its existence (NFR-SEC-43). The
// host-derived caller is the authority; the body hint only ADDRESSES the caller's
// own namespace.
func (h *Handlers) Status(ctx context.Context, _ ingress.ServiceScope, conn ingress.ConnInfo, sessionHint string) (state.SessionRow, error) {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return state.SessionRow{}, err
	}
	return h.manager.Status(ctx, caller, sessionHint)
}

// Exec runs one command in the caller's OWN session guest. The host-derived caller
// gates the row lookup exactly as Destroy/Status do — a foreign or absent
// sessionHint yields registry.ErrNotOwned (indistinguishable from not-found), so a
// service caller can neither exec into another tenant's session nor probe its
// existence (NFR-SEC-43). The body carries the command and its optional
// environment, working directory, stdin, and timeout as intents; identity is never
// a field here.
func (h *Handlers) Exec(ctx context.Context, _ ingress.ServiceScope, conn ingress.ConnInfo, sessionHint string, req lifecycle.ExecRequest) (lifecycle.ExecResult, error) {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return lifecycle.ExecResult{}, err
	}
	return h.manager.Exec(ctx, caller, sessionHint, req)
}

// CreateRequest is the body of a gateway create. Its fields are HINTS carried onto
// the lifecycle CreateInput; the authority is the host-derived caller the resolver
// produced from the verified SAN, never any field here (NFR-SEC-43).
type CreateRequest struct {
	// SessionHint seeds the host-minted handle; it never becomes the Key.
	SessionHint string
	// Image is the sandbox image reference the provider runs.
	Image string
	// Mount is the per-session storage mount intent (AuthToken is a later-phase
	// placeholder).
	Mount runtime.MountIntent
	// Egress is the per-session egress trust-edge policy.
	Egress runtime.EgressPolicy
	// Resources are the hard caps stamped onto the runtime.
	Resources runtime.ResourceCaps
}

// Listener is the gateway TCP/mTLS listener. It owns the bound socket, the
// verified-SAN dispatch, and the Handlers surface. Bind establishes the TCP (and,
// when configured, mTLS) socket; Serve accepts connections, extracts the verified
// SANs, and dispatches; Close stops it. It is constructed only after a clean
// kill-switch-first Boot, off the readiness hook, so it can never bind before the
// deny posture is durable.
type Listener struct {
	handlers  *Handlers
	addr      string
	tlsConfig *tls.Config
	scope     ingress.ServiceScope
	ln        net.Listener
}

// NewListener builds the gateway listener bound (logically) to addr. It does NOT
// open the socket — Bind does — so a construction in cmd cannot bind ahead of the
// readiness gate. addr is the host:port TCP endpoint (any scheme stripped by the
// caller). The ServiceScope is minted here (no seam required); the verified SAN is
// the real authority.
func NewListener(addr string, deps Deps) *Listener {
	return &Listener{
		handlers:  NewHandlers(deps),
		addr:      addr,
		tlsConfig: deps.TLSConfig,
		scope:     ingress.ServiceScopeFor(),
	}
}

// Handlers exposes the in-process service surface for direct (transport-free)
// driving and testing.
func (l *Listener) Handlers() *Handlers { return l.handlers }

// Scope returns the gateway's ServiceScope, the capability the service handlers
// take. There is no OperatorScope here and no way to obtain one.
func (l *Listener) Scope() ingress.ServiceScope { return l.scope }

// Bind opens the gateway TCP socket and wraps it in the mTLS config when one is
// supplied, fail-closed: a bind failure returns the error and leaves no listener.
// With no TLS config it binds plain TCP whose connections carry no verified SAN,
// so every Resolve fails closed (a clearly-stubbed, fail-closed posture). Bind is
// called only from the boot readiness hook, strictly after the deny posture is
// durable.
func (l *Listener) Bind() error {
	tcp, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("gateway: bind tcp %q: %w", l.addr, err)
	}
	if l.tlsConfig != nil {
		l.ln = tls.NewListener(tcp, l.tlsConfig)
	} else {
		l.ln = tcp
	}
	return nil
}

// Addr returns the bound address, or empty before Bind. It is for diagnostics and
// the self-probe health check.
func (l *Listener) Addr() string {
	if l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}

// Close stops the listener. It is idempotent against a never-bound listener.
func (l *Listener) Close() error {
	if l.ln == nil {
		return nil
	}
	if err := l.ln.Close(); err != nil {
		return fmt.Errorf("gateway: close listener: %w", err)
	}
	return nil
}

// verifiedSANsOf extracts the VERIFIED client-cert SANs from a completed TLS
// handshake state. It reads ONLY VerifiedChains (chains the TLS stack already
// verified against the trust anchor), never the raw presented certificate, so an
// attacker cannot inject a SAN by presenting an unverified cert. A nil state or a
// handshake with no verified chain yields an empty slice, which makes the resolver
// fail closed. It takes the *tls.ConnectionState (rather than a net.Conn) so the
// caller reads it from the handshake-complete *http.Request.TLS — the only point a
// verified chain is observable.
func verifiedSANsOf(st *tls.ConnectionState) []string {
	if st == nil || len(st.VerifiedChains) == 0 {
		return nil
	}
	// The leaf of the first verified chain is the client's verified certificate.
	leaf := st.VerifiedChains[0][0]
	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.URIs))
	sans = append(sans, leaf.DNSNames...)
	for _, u := range leaf.URIs {
		sans = append(sans, u.String())
	}
	return sans
}

// errNotBound is returned by Serve when called before Bind.
var errNotBound = errors.New("gateway: Serve called before Bind (no bound socket)")
