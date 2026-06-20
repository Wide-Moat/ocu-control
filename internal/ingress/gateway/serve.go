// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/registry"
)

// readHeaderTimeout bounds how long the gateway server waits for a request's
// headers, closing a connection that dribbles them (a Slowloris guard). The
// gateway plane faces in-workforce services, so the bound matters here; it also
// keeps gosec satisfied that no header read is unbounded.
const readHeaderTimeout = 10 * time.Second

// connInfoKey is the unexported context key under which each accepted
// connection's resolved ingress.ConnInfo is threaded to its HTTP handlers. It is a
// distinct unexported type so no other package can collide with or read the key.
type connInfoKey struct{}

// Serve runs the minimal mTLS-shaped HTTP transport on the bound listener until
// ctx is cancelled. It mounts the SERVICE surface ONLY — create, destroy, status —
// and is the sufficient-for-Phase-3 wire to drive the gateway plane; the full
// gateway proto/OpenAPI is a follow-up. Each accepted connection's VERIFIED
// client-cert SANs are extracted once at accept time (ConnContext) and threaded
// onto the request context, so a handler reads the host-attested service identity
// without re-touching the socket. A connection with no verified SAN carries an
// unattested ConnInfo and every handler refuses it fail-closed.
//
// Serve must be called only after Bind and only from the boot readiness hook, so
// the socket exists strictly after the deny posture is durable. It returns nil on
// a clean ctx-driven shutdown and the server error otherwise. NO operator route is
// mounted here — the gateway plane reaches no operator-only method.
func (l *Listener) Serve(ctx context.Context) error {
	if l.ln == nil {
		return errNotBound
	}

	mux := http.NewServeMux()
	l.registerRoutes(mux)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		// ConnContext marks every request on this connection as arriving on the gateway
		// channel. The VERIFIED SANs are NOT read here: ConnContext runs at accept time,
		// BEFORE the TLS handshake completes, so tls.Conn.ConnectionState() would carry no
		// verified chain yet. The SANs are derived per request in connInfoFromRequest from
		// the handshake-complete *http.Request.TLS, which is the only point a verified
		// chain is observable.
		ConnContext: func(connCtx context.Context, _ net.Conn) context.Context {
			return context.WithValue(connCtx, connInfoKey{}, ingress.ChannelGateway)
		},
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	err := srv.Serve(l.ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("gateway: serve: %w", err)
	}
	return nil
}

// connInfoFromRequest builds the ingress.ConnInfo for one request: the gateway
// channel (marked by the ConnContext hook) plus the VERIFIED client-cert SANs read
// from r.TLS. r.TLS is populated by the server only after the TLS handshake
// completes, so its VerifiedChains carry the chain the TLS stack verified against
// the trust anchor — the correct, and only sound, point to read a verified SAN
// (ConnContext runs pre-handshake and would see none). A request not served through
// Serve, or one with no completed mTLS handshake, yields an unattested ConnInfo
// (nil CertSANs) so the handler refuses fail-closed.
func connInfoFromRequest(r *http.Request) ingress.ConnInfo {
	info := ingress.ConnInfo{Channel: ingress.ChannelGateway}
	if _, ok := r.Context().Value(connInfoKey{}).(ingress.Channel); !ok {
		// Not served through Serve: still gateway-channel, but with no verified SAN it
		// fails closed at the resolver.
		return info
	}
	if r.TLS != nil {
		info.CertSANs = verifiedSANsOf(r.TLS)
	}
	return info
}

// registerRoutes mounts the gateway SERVICE surface onto mux: create, destroy,
// status. Each handler pulls the per-connection host-attested ConnInfo, mints the
// listener's ServiceScope, and drives the matching Handlers method. The bodies are
// a minimal JSON shape sufficient to exercise create→destroy→status end-to-end;
// the full gateway proto wire is a follow-up. There is NO revoke/denylist/quota
// route here — those live on the operator plane and are unreachable from this
// package as a compile fact.
func (l *Listener) registerRoutes(mux *http.ServeMux) {
	h := l.handlers
	scope := l.scope

	mux.HandleFunc("/v1alpha/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body createBody
		if err := decodeJSON(r, &body); err != nil {
			writeStatus(w, http.StatusBadRequest, "invalid request body")
			return
		}
		row, err := h.Create(r.Context(), scope, conn, body.toRequest())
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, sessionResponse{Key: row.Key, State: int(row.State)})
	})

	mux.HandleFunc("/v1alpha/sessions/destroy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body hintBody
		if err := decodeJSON(r, &body); err != nil {
			writeStatus(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := h.Destroy(r.Context(), scope, conn, body.SessionHint); err != nil {
			writeServiceError(w, err)
			return
		}
		writeStatus(w, http.StatusOK, "destroyed")
	})

	mux.HandleFunc("/v1alpha/sessions/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body hintBody
		if err := decodeJSON(r, &body); err != nil {
			writeStatus(w, http.StatusBadRequest, "invalid request body")
			return
		}
		row, err := h.Status(r.Context(), scope, conn, body.SessionHint)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, sessionResponse{Key: row.Key, State: int(row.State)})
	})
}

// createBody is the minimal JSON create request. SessionHint and the runtime
// fields are HINTS; the host-attested caller is derived from the verified SAN,
// never the body (NFR-SEC-43).
type createBody struct {
	SessionHint   string `json:"session_hint"`
	Image         string `json:"image"`
	ControlPubKey []byte `json:"control_pub_key"`
}

// toRequest maps the wire body to the in-process CreateRequest.
func (b createBody) toRequest() CreateRequest {
	return CreateRequest{
		SessionHint:   b.SessionHint,
		Image:         b.Image,
		ControlPubKey: b.ControlPubKey,
	}
}

// hintBody is the minimal destroy/status request: a session hint that ADDRESSES
// the caller's own row through the host-derived key.
type hintBody struct {
	SessionHint string `json:"session_hint"`
}

// sessionResponse is the minimal session body: the host-derived key and the
// numeric lifecycle state. The container name is intentionally omitted — it is
// recorded data, never returned as addressable authority.
type sessionResponse struct {
	Key   string `json:"key"`
	State int    `json:"state"`
}

// decodeJSON decodes the request body into v, rejecting unknown fields. An empty
// body decodes to the zero value.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// writeStatus writes a plain-text status line with the given code.
func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(msg))
}

// writeJSON writes v as a JSON body with the given code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeServiceError maps a service error onto an HTTP status without disclosing
// cross-tenant existence. An unattested caller is 401; ErrNotOwned and a collapsed
// not-found are both 404 (indistinguishable); any other refusal is 409.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingress.ErrUnattested) || errors.Is(err, lifecycle.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	case errors.Is(err, registry.ErrNotOwned):
		writeStatus(w, http.StatusNotFound, "session not addressable")
	default:
		writeStatus(w, http.StatusConflict, "request refused")
	}
}
