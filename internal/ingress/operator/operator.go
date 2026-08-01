// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package operator is the operator/lifecycle ingress adapter: the Unix-socket
// listener the host operator, the admin API, and the SOAR webhook converge on. It
// is the ONE adapter that holds the ingress.OperatorSeam (cmd hands it the single
// seam NewOperatorSeam produced), so it is the only place an ingress.OperatorScope
// can be minted and therefore the only place the kill-switch and the other
// operator-only privileged ops (denylist edit, quota override, force-kill destroy)
// can be reached. The gateway adapter holds no seam and has no import path to the
// mint, so a gateway call to an operator-only method does not compile — the
// import-graph test and the compile-fail fixture keep that load-bearing.
//
// Host-attested identity (NFR-SEC-43). Every accepted connection's caller is
// derived from SO_PEERCRED via the build-tagged PeerCredResolver — the kernel
// vouches for the uid/gid/pid, and a request body never populates the identity. An
// unattested connection (no peer creds, or any non-Linux build where SO_PEERCRED
// does not exist) is refused with ingress.ErrUnattested BEFORE any handler runs and
// before any host state is touched.
//
// Two authentication shapes meet here. The admin-API and CLI channels authenticate
// by the host-owned 0700 socket plus the peer credential — possession of an
// operator-scoped connection IS the operator credential, so the adapter mints the
// OperatorScope for those channels once the peer is attested. The SOAR webhook is
// untrusted transport: its payload+signature run through the SOARVerifier and the
// scope is minted ONLY on a successful verify (verify-then-mint, P2-R2), so an
// unverifiable SOAR call yields no scope and cannot even form an Engine call.
//
// The transport here is a minimal HTTP-over-Unix mux sufficient to drive and test
// create→destroy and the kill-switch end-to-end; the full operator-REST/SOAR wire
// schema is authored separately. The handler SHAPES (the Handlers methods) are the
// stable in-process surface the transport and the tests both call.
package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// socketDirPerm is the 0700 mode on the directory holding the operator socket:
// owner-only, so no other host user can connect to the privileged operator plane.
const socketDirPerm = 0o700

// Deps are the collaborators the operator adapter drives. The Manager runs the
// lifecycle create/destroy pipeline; the Engine authors revokes, denylist edits,
// and quota overrides (all operator-scoped); the Healthz handler is mounted from
// the boot Sequencer; the Resolver derives the host-attested caller; the Verifier
// gates the SOAR channel. The Seam is the single operator capability — it is held
// by this adapter ALONE.
type Deps struct {
	// Manager runs the lifecycle create/destroy pipeline.
	Manager *lifecycle.Manager
	// Engine authors the durable deny posture and the operator-scoped overrides.
	Engine *killswitch.Engine
	// Healthz is the readiness handler the boot Sequencer exposes; the adapter
	// mounts it on the operator socket.
	Healthz HealthzFunc
	// Resolver derives the host-attested caller from an accepted connection.
	// Defaults to NewPeerCredResolver(nil) when nil.
	Resolver ingress.IdentityResolver
	// Verifier gates the SOAR channel (verify-then-mint). When nil the SOAR path
	// refuses fail-closed (no verifier configured).
	Verifier killswitch.SOARVerifier
	// Seam is the single operator capability this adapter holds. cmd mints exactly
	// one OperatorSeam and hands it here alone; the gateway adapter is given none.
	Seam ingress.OperatorSeam
	// Reader is the narrow read port the admin read-surface consumes (the enriched
	// live-session enumeration through the sole custodian). It is SEPARATE from the
	// mutating surfaces: the read handler is given only this and the deployment
	// singletons, never the Seam/Manager/Engine, so the read-only boundary holds
	// structurally (ADR-0022). When nil the read routes are not mounted.
	Reader SessionReader
	// Deployment is the pair of deployment-wide singletons (runtime tier and
	// provider) the read surface reports, chosen once at boot (ADR-0003).
	Deployment DeploymentInfo
	// Metrics is the Prometheus exposition handler mounted at GET /metrics on the
	// operator plane (the admin console scrapes it). It is passed as a plain
	// http.Handler so this package stays decoupled from the metrics collector. When
	// nil the /metrics route is not mounted.
	Metrics http.Handler
	// MCPKeyEngine is the operator surface for minting and revoking sk-ocu- MCP API
	// keys. Its Create/Revoke methods require an OperatorScope (obtained here from the
	// held Seam after attestation) so a gateway caller cannot reach them. When nil the
	// MCPKeyCreate/MCPKeyRevoke handlers refuse with an internal error — the daemon
	// wires the real engine; tests may inject a configured one. It is SEPARATE from the
	// killswitch Engine: MCP key operations do not touch the session denylist.
	MCPKeyEngine *mcpkey.Engine
}

// HealthzFunc is the readiness handler the boot Sequencer's Healthz returns. The
// adapter mounts it on the operator socket so /healthz reports readiness on the
// privileged plane; the gateway plane never serves it.
type HealthzFunc = http.HandlerFunc

// Handlers is the stable in-process operator surface. Each method takes the
// transport-neutral ingress.ConnInfo the listener resolved (carrying the
// kernel-attested PeerCred), derives the host-attested caller, and performs one
// operator operation. The kill-switch and override methods mint the OperatorScope
// from the held seam (after peer attestation for admin/CLI, after a SOAR verify
// for the webhook), so the operator-only Engine surface is reachable only here.
type Handlers struct {
	manager      *lifecycle.Manager
	engine       *killswitch.Engine
	mcpKeyEngine *mcpkey.Engine
	resolver     ingress.IdentityResolver
	verifier     killswitch.SOARVerifier
	seam         ingress.OperatorSeam
}

// NewHandlers builds the in-process operator handler surface from Deps. A nil
// Resolver defaults to the host-derived peer-cred resolver. It does not bind a
// socket — Listener does that — so the handlers are unit-testable with a synthetic
// ConnInfo and no transport.
func NewHandlers(deps Deps) *Handlers {
	resolver := deps.Resolver
	if resolver == nil {
		resolver = NewPeerCredResolver(nil)
	}
	return &Handlers{
		manager:      deps.Manager,
		engine:       deps.Engine,
		mcpKeyEngine: deps.MCPKeyEngine,
		resolver:     resolver,
		verifier:     deps.Verifier,
		seam:         deps.Seam,
	}
}

// resolveCaller derives the host-attested caller from conn through the operator
// resolver. It is the single gate every operator handler runs first: an unattested
// connection is refused with ingress.ErrUnattested before any host state is
// touched. The Channel on the returned caller is always ChannelOperator.
func (h *Handlers) resolveCaller(ctx context.Context, conn ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	caller, err := h.resolver.Resolve(ctx, conn)
	if err != nil {
		return ingress.AuthenticatedCaller{}, err
	}
	return caller, nil
}

// Create runs the lifecycle create pipeline for an operator-channel caller. The
// caller is host-derived from peer creds; the body fields (image, hint, mount) are
// hints carried onto the CreateInput, never identity. It returns the host-assigned
// SessionRow on success or the typed stage error on a refusal/rollback.
func (h *Handlers) Create(ctx context.Context, conn ingress.ConnInfo, req CreateRequest) (state.SessionRow, error) {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return state.SessionRow{}, err
	}
	in := lifecycle.CreateInput{
		Caller:      caller,
		SessionHint: req.SessionHint,
		Image:       req.Image,
		Mounts:      req.Mounts,
		Egress:      req.Egress,
		Resources:   req.Resources,
	}
	return h.manager.Create(ctx, in)
}

// Destroy runs the lifecycle destroy path for an operator-channel caller. The
// host-derived caller gates the row lookup; a foreign sessionHint yields
// registry.ErrNotOwned (indistinguishable from not-found), never the victim's
// teardown.
func (h *Handlers) Destroy(ctx context.Context, conn ingress.ConnInfo, sessionHint string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	return h.manager.Destroy(ctx, caller, sessionHint)
}

// RevokeOne denylists a single session and force-kills its live row. The
// admin/CLI channel is authenticated by the attested operator socket, so the
// scope is minted from the held seam once the caller is attested. A gateway-shaped
// caller can reach none of this: it holds no seam, so the Mint below would not
// compile in its package.
func (h *Handlers) RevokeOne(ctx context.Context, conn ingress.ConnInfo, key, reason string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	// The host-attested socket peer IS the operator for the admin/CLI channel, so the
	// scope is stamped with caller.Identity — the audit actor is WHO ACTED.
	scope := h.seam.Mint(caller.Identity)
	return h.engine.RevokeOne(ctx, scope, key, reason)
}

// RevokeAll engages the deployment-wide DENY-ALL and force-kills every live row.
// As with RevokeOne the admin/CLI channel authenticates via the attested operator
// socket and the scope is minted from the held seam after attestation.
func (h *Handlers) RevokeAll(ctx context.Context, conn ingress.ConnInfo, reason string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	// The attested socket peer is the operator for the admin/CLI channel; the scope
	// carries caller.Identity as the audit actor.
	scope := h.seam.Mint(caller.Identity)
	return h.engine.RevokeAll(ctx, scope, reason)
}

// ResumeAll lifts the deployment-wide DENY-ALL — the operator-only in-band
// counterpart to RevokeAll. As with RevokeAll the admin/CLI channel authenticates
// via the attested operator socket and the scope is minted from the held seam after
// attestation; a gateway-shaped caller holds no seam, so the Mint below would not
// compile in its package, and no gateway route reaches this handler (NFR-SEC-52).
func (h *Handlers) ResumeAll(ctx context.Context, conn ingress.ConnInfo, reason string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	// The attested socket peer is the operator for the admin/CLI channel; the scope
	// carries caller.Identity as the audit actor.
	scope := h.seam.Mint(caller.Identity)
	return h.engine.ResumeAll(ctx, scope, reason)
}

// RevokeOneViaSOAR is the SOAR-webhook revoke path: it runs verify-then-mint, so
// the OperatorScope exists ONLY after the SOAR signature is verified. The
// connection itself is still attested (the webhook arrives on the operator
// socket), but the SOAR principal's signature — not the socket — is the authority
// for a SOAR-driven revoke (P2-R2). An unverifiable signature yields
// killswitch.ErrSOARUnverified and no Engine call is formed.
//
// UNMOUNTED, deliberately. This handler is fully tested (handlers_test.go,
// operator_test.go) but registerRoutes mounts NO HTTP route that reaches it: the
// SOAR-webhook transport is DEFERRED, not missing by accident. The absence of a
// route is the same #205 deferral as the draft contract that mirrors this path —
// the HTTP route lands together with the #205 SOAR wire. Mount is gated on the
// frozen #205 soar-revoke.openapi.yaml; the route shape derives from that frozen
// contract, not invented here. soar_fence_test.go enforces that nothing mounts a
// SOAR route before that contract freezes.
func (h *Handlers) RevokeOneViaSOAR(ctx context.Context, conn ingress.ConnInfo, payload, sig []byte, key, reason string) error {
	if _, err := h.resolveCaller(ctx, conn); err != nil {
		return err
	}
	scope, err := verifyThenMint(ctx, h.verifier, h.seam, payload, sig)
	if err != nil {
		return err
	}
	return h.engine.RevokeOne(ctx, scope, key, reason)
}

// RevokeAllViaSOAR is the SOAR-webhook DENY-ALL path, the verify-then-mint
// analogue of RevokeAll. The scope is minted only after the SOAR signature
// verifies. Like RevokeOneViaSOAR this handler is tested but UNMOUNTED: no
// registerRoutes route reaches it, and the mount is gated on the frozen #205
// soar-revoke.openapi.yaml (see RevokeOneViaSOAR and soar_fence_test.go).
func (h *Handlers) RevokeAllViaSOAR(ctx context.Context, conn ingress.ConnInfo, payload, sig []byte, reason string) error {
	if _, err := h.resolveCaller(ctx, conn); err != nil {
		return err
	}
	scope, err := verifyThenMint(ctx, h.verifier, h.seam, payload, sig)
	if err != nil {
		return err
	}
	return h.engine.RevokeAll(ctx, scope, reason)
}

// LiftDeny lifts a per-session deny entry (the operator denylist edit). The
// admin/CLI channel authenticates via the attested socket and the scope is minted
// from the held seam.
//
// DEFERRED ROUTE: this handler is complete and tested in-process but its HTTP route
// is deliberately not mounted yet (mounted with the denylist-edit wire route). It is
// on the deferredHandlers allow-list, which TestDeferredHandlers_AllowListIsExact
// enforces — a dead-code pass cannot delete it, and a premature mount fails the
// build. It is the same design-fenced class as the SOAR-revoke pair.
func (h *Handlers) LiftDeny(ctx context.Context, conn ingress.ConnInfo, key, reason string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	// The attested socket peer is the operator for the admin/CLI channel; the scope
	// carries caller.Identity as the audit actor.
	scope := h.seam.Mint(caller.Identity)
	return h.engine.LiftDeny(ctx, scope, key, reason)
}

// OverrideQuota applies an operator-authored delta to a counter cell through the
// atomic Charge. The admin/CLI channel authenticates via the attested socket; the
// scope is minted from the held seam.
//
// DEFERRED ROUTE: this handler is complete and tested in-process but its HTTP route
// is deliberately not mounted yet (mounted with the quota-override wire route). It
// is on the deferredHandlers allow-list, which TestDeferredHandlers_AllowListIsExact
// enforces — a dead-code pass cannot delete it, and a premature mount fails the
// build. It is the same design-fenced class as the SOAR-revoke pair.
func (h *Handlers) OverrideQuota(ctx context.Context, conn ingress.ConnInfo, key state.QuotaKey, delta, limit int64, reason string) error {
	caller, err := h.resolveCaller(ctx, conn)
	if err != nil {
		return err
	}
	// The attested socket peer is the OPERATOR who issued the override; the scope
	// carries caller.Identity as the audit actor (actor.user = who acted), distinct
	// from the quota TARGET in key that the Engine charges.
	scope := h.seam.Mint(caller.Identity)
	return h.engine.OverrideQuota(ctx, scope, key, delta, limit, reason)
}

// CreateRequest is the body of an operator create. Its fields are HINTS carried
// onto the lifecycle CreateInput; the authority is the host-derived caller the
// resolver produced, never any field here (NFR-SEC-43).
type CreateRequest struct {
	// SessionHint seeds the host-minted handle; it never becomes the Key.
	SessionHint string
	// Image is the sandbox image reference the provider runs.
	Image string
	// Mounts are the per-session storage mount intents, one per guest
	// mountpoint (AuthToken is a later-phase placeholder).
	Mounts []runtime.MountIntent
	// Egress is the per-session egress trust-edge policy.
	Egress runtime.EgressPolicy
	// Resources are the hard caps stamped onto the runtime.
	Resources runtime.ResourceCaps
}

// Listener is the operator Unix-socket listener. It owns the bound socket, the
// resolved-caller dispatch, and the Handlers surface. Bind establishes the
// host-owned 0700 socket; Serve accepts connections, derives the peer credential,
// and dispatches; Close removes the socket. It is constructed only after a clean
// kill-switch-first Boot, off the readiness hook, so it can never bind before the
// deny posture is durable.
type Listener struct {
	handlers *Handlers
	read     *ReadHandlers
	healthz  HealthzFunc
	metrics  http.Handler
	socket   string
	ln       net.Listener
}

// NewListener builds the operator listener bound (logically) to socketPath. It
// does NOT open the socket — Bind does — so a construction in cmd cannot bind
// ahead of the readiness gate. socketPath is the filesystem path of the Unix
// socket (the operator endpoint with any unix:// scheme stripped by the caller).
func NewListener(socketPath string, deps Deps) *Listener {
	l := &Listener{
		handlers: NewHandlers(deps),
		healthz:  deps.Healthz,
		metrics:  deps.Metrics,
		socket:   socketPath,
	}
	// The read surface is mounted only when a reader is supplied. It is built with
	// the SAME resolver the mutating handlers use (so attestation is identical) but
	// is given NEITHER the Seam nor any mutating surface, so it cannot reach a
	// reservation mutator, the denylist, or a quota override.
	if deps.Reader != nil {
		resolver := deps.Resolver
		if resolver == nil {
			resolver = NewPeerCredResolver(nil)
		}
		l.read = NewReadHandlers(deps.Reader, resolver, deps.Deployment)
	}
	return l
}

// Handlers exposes the in-process operator surface for direct (transport-free)
// driving and testing. The full create→destroy and kill-switch flows are exercised
// against this surface with a synthetic ConnInfo, so the proof harness needs no
// bound socket.
func (l *Listener) Handlers() *Handlers { return l.handlers }

// Bind opens the operator Unix socket under a host-owned 0700 directory,
// fail-closed: it creates the parent directory 0700, removes any stale socket
// file, and binds. A bind failure returns the error and leaves no listener, so a
// caller that fails to bind has opened nothing. Bind is called only from the boot
// readiness hook, strictly after the deny posture is durable.
func (l *Listener) Bind() error {
	dir := filepath.Dir(l.socket)
	if err := os.MkdirAll(dir, socketDirPerm); err != nil {
		return fmt.Errorf("operator: create socket dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, socketDirPerm); err != nil {
		return fmt.Errorf("operator: chmod socket dir %q: %w", dir, err)
	}
	// Remove a stale socket from a previous run; a bind onto an existing path fails
	// with "address already in use" otherwise. Removing a non-socket here is guarded
	// by the 0700 host-owned dir.
	if err := removeStaleSocket(l.socket); err != nil {
		return fmt.Errorf("operator: remove stale socket %q: %w", l.socket, err)
	}
	ln, err := net.Listen("unix", l.socket)
	if err != nil {
		return fmt.Errorf("operator: bind unix socket %q: %w", l.socket, err)
	}
	l.ln = ln
	return nil
}

// removeStaleSocket removes an existing socket file at path, treating an absent
// path as success. It refuses to remove a path that is not a socket, so a
// misconfigured operator endpoint pointing at a real file is a hard error rather
// than a silent deletion.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("path exists and is not a socket")
	}
	return os.Remove(path)
}

// Addr returns the bound socket path, or empty before Bind. It is for diagnostics
// and the self-probe health check.
func (l *Listener) Addr() string {
	if l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}

// Close removes the listener and its socket file. It is idempotent against a
// never-bound listener.
func (l *Listener) Close() error {
	if l.ln == nil {
		return nil
	}
	err := l.ln.Close()
	// net.Listen on a unix socket removes the file on Close in the stdlib, but a
	// belt-and-braces remove keeps a re-bind clean if the runtime left it behind.
	_ = os.Remove(l.socket)
	if err != nil {
		return fmt.Errorf("operator: close listener: %w", err)
	}
	return nil
}
