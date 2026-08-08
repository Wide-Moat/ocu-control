// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// readHeaderTimeout bounds how long the server waits for a request's headers,
// closing a connection that dribbles them (a Slowloris guard). The operator plane
// is a trusted local socket, but the bound is cheap insurance and keeps gosec
// satisfied that no header read is unbounded.
const readHeaderTimeout = 10 * time.Second

// readTimeout bounds the whole-request read (headers plus body), defeating a slow
// body that dribbles bytes under the header timeout. 30s suits a small-JSON
// operator surface without breaking a legitimate slow client on the local socket.
const readTimeout = 30 * time.Second

// idleTimeout bounds an idle keep-alive connection so a parked socket is reaped
// rather than held open indefinitely.
const idleTimeout = 120 * time.Second

// connInfoKey is the unexported context key under which each accepted
// connection's resolved ingress.ConnInfo is threaded to its HTTP handlers. It is a
// distinct unexported type so no other package can collide with or read the key.
type connInfoKey struct{}

// Serve runs the minimal HTTP-over-Unix transport on the bound listener until ctx
// is cancelled. It mounts the readiness handler at /healthz and is the sufficient-
// for-Phase-3 wire to drive the operator plane; the full operator-REST/SOAR
// OpenAPI is a follow-up. Each accepted connection's kernel-attested PeerCred is
// resolved once at accept time (ConnContext) and threaded onto the request
// context, so a handler that needs the host-attested caller reads it without
// re-touching the socket. A connection whose peer credential cannot be read
// carries an unattested ConnInfo and any handler that resolves identity refuses it
// fail-closed.
//
// Serve must be called only after Bind and only from the boot readiness hook, so
// the socket exists strictly after the deny posture is durable. It returns nil on
// a clean ctx-driven shutdown and the server error otherwise.
func (l *Listener) Serve(ctx context.Context) error {
	if l.ln == nil {
		return errors.New("operator: Serve called before Bind (no bound socket)")
	}

	mux := http.NewServeMux()
	if l.healthz != nil {
		mux.Handle("/healthz", l.healthz)
	}
	if l.metrics != nil {
		// The Prometheus scrape endpoint lives on the operator plane only (the admin
		// console scrapes it through the same host-attested transport); the gateway
		// plane never serves it.
		mux.Handle("GET /metrics", l.metrics)
	}
	l.registerRoutes(mux)

	srv := newServer(ctx, l.admissionGate(mux))

	// Shut the server down when ctx is cancelled so a caller's lifecycle drives the
	// listener's lifetime; Serve returns http.ErrServerClosed on that path, which we
	// normalize to nil.
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	err := srv.Serve(l.ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("operator: serve: %w", err)
	}
	return nil
}

// priorityRoutes is the kill-switch family whose admission draws on the reserved
// pool first: revoke-one, revoke-all, and the in-band DENY-ALL lift (resume-all).
// A request whose path is one of these is ClassPriority; everything else on the
// operator plane (create, destroy, read, quota-override, mcp-key) is ClassGeneral.
// The set is matched by exact path so a new operator route defaults to general
// unless it is deliberately added here — a revoke route must never silently lose
// its reservation, and a non-revoke route must never silently gain it.
var priorityRoutes = map[string]struct{}{
	"/v1alpha/revoke/one": {},
	"/v1alpha/revoke/all": {},
	"/v1alpha/resume/all": {},
}

// classOf maps a request path to its admission class. The health and metrics
// endpoints are ClassPriority so a flood on the mutating surface cannot starve a
// liveness scrape or the readiness probe the boot sequencer depends on.
func classOf(path string) admit.Class {
	switch path {
	case "/healthz", "/metrics":
		return admit.ClassPriority
	}
	if _, ok := priorityRoutes[path]; ok {
		return admit.ClassPriority
	}
	return admit.ClassGeneral
}

// callerRateKey derives the per-caller rate-limit key from the HOST-ATTESTED
// PeerCred UID stamped on the connection by the ConnContext hook — never a request
// body or header, so a caller cannot spoof a fresh bucket. An unattested connection
// (nil PeerCred) shares one "unattested" key so an unattested flood is throttled as
// a single principal; such requests are refused fail-closed by the handler anyway,
// but sharing a bucket keeps them from each opening a private allowance.
func callerRateKey(r *http.Request) string {
	conn := connInfoFromRequest(r)
	if conn.PeerCred == nil {
		return "unattested"
	}
	return "uid:" + strconv.FormatUint(uint64(conn.PeerCred.UID), 10)
}

// admissionGate wraps next with the SEC-55 bounded admission: every request
// acquires a gate slot before it reaches a handler and releases it after. A
// priority (revoke/resume/health) request draws on the reserved pool and admits
// even while a general flood holds every general slot; a general request waits at
// most admitWait for a general slot and is shed with 503 + Retry-After if the pool
// stays saturated, so a flood sheds load rather than queuing unboundedly. The gate
// is acquired under the REQUEST context so a client that hangs up frees its wait
// immediately.
func (l *Listener) admissionGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		class := classOf(r.URL.Path)

		// Per-caller fairness (SEC-55): a GENERAL request over its host-attested
		// caller's rate is throttled with 429 so one principal cannot monopolize the
		// general pool. A PRIORITY (revoke) request is NEVER rate-throttled — the kill
		// switch must fire even from a caller that has saturated its own rate.
		if class == admit.ClassGeneral && l.limiter != nil && !l.limiter.Allow(callerRateKey(r)) {
			if l.admitMx != nil {
				l.admitMx.IncAdmissionThrottled()
			}
			w.Header().Set("Retry-After", "1")
			writeStatus(w, http.StatusTooManyRequests, "per-caller operator rate exceeded; retry")
			return
		}

		acqCtx := r.Context()
		// A general request gets a bounded wait so a saturated general pool sheds
		// rather than piling goroutines; a priority request is not subject to the
		// general-flood wait — it draws on the reserved pool.
		if class == admit.ClassGeneral {
			var cancel context.CancelFunc
			acqCtx, cancel = context.WithTimeout(acqCtx, l.admitWait)
			defer cancel()
		}

		release, ok := l.gate.Acquire(acqCtx, class)
		if !ok {
			// Shed: the general pool stayed saturated past admitWait (or the client
			// hung up). 503 with Retry-After is the load-shed signal, distinct from a
			// 4xx deny — the request was well-formed, the plane is momentarily full.
			if l.admitMx != nil {
				l.admitMx.IncAdmissionShed()
			}
			w.Header().Set("Retry-After", "1")
			writeStatus(w, http.StatusServiceUnavailable, "operator ingress saturated; retry")
			return
		}
		defer release()
		next.ServeHTTP(w, r)
	})
}

// newServer builds the operator HTTP server with the bounded read/idle posture and
// the per-connection PeerCred ConnContext hook. It is factored out of Serve so the
// timeout wiring is unit-observable: the read header, whole-request read, and idle
// bounds are all non-zero and assertable on the returned *http.Server. The mux
// passed in already carries the routes Serve mounts (healthz, the metrics scrape
// endpoint when configured, and the registerRoutes surface).
//
// WriteTimeout is deliberately not set: Serve drives shutdown via ctx.Done →
// srv.Close and the handlers are fast unary JSON, so the read+idle pair is the
// load-bearing defence against a slow body, and a write bound would only risk
// truncating a legitimate slow consumer without adding Slowloris protection.
func newServer(ctx context.Context, mux http.Handler) *http.Server {
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		// ConnContext resolves the kernel-attested PeerCred ONCE per connection and
		// stashes the ConnInfo on the base context every request on that connection
		// inherits. A failed resolve stashes an unattested ConnInfo (the zero value),
		// so a handler's identity gate refuses fail-closed rather than reading a body.
		ConnContext: func(connCtx context.Context, c net.Conn) context.Context {
			info, err := connCredOf(c)
			if err != nil {
				// Carry an unattested ConnInfo: it has a nil PeerCred, so the resolver
				// refuses with ingress.ErrUnattested before any host state is touched.
				info = ingress.ConnInfo{Channel: ingress.ChannelOperator}
			}
			// The latch and the conn identity are stamped on BOTH arms: an
			// unattested connection's failed resolutions are exactly the records
			// the failure half of the authentication trail exists for (#107).
			info.ConnID = ingress.NextConnID()
			connCtx = ingress.WithAuthnLatch(connCtx)
			return context.WithValue(connCtx, connInfoKey{}, info)
		},
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
}

// connInfoFromRequest extracts the per-connection ingress.ConnInfo the ConnContext
// hook stashed, for an HTTP handler that drives an operator op. An absent value
// (a request not served through Serve) yields an unattested ConnInfo so the
// handler refuses fail-closed.
func connInfoFromRequest(r *http.Request) ingress.ConnInfo {
	if info, ok := r.Context().Value(connInfoKey{}).(ingress.ConnInfo); ok {
		return info
	}
	return ingress.ConnInfo{Channel: ingress.ChannelOperator}
}
