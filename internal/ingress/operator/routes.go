// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/registry"
)

// registerRoutes mounts the minimal operator HTTP surface onto mux: create,
// destroy, and the two revoke verbs. Each handler pulls the per-connection
// host-attested ConnInfo the ConnContext hook stashed and drives the matching
// Handlers method, so the transport reuses the exact in-process surface the tests
// drive directly. The bodies are a minimal JSON shape sufficient to exercise
// create→destroy and the kill-switch end-to-end; the full operator-REST wire is a
// follow-up. This is the operator plane ONLY — none of these routes is ever
// mounted on the gateway listener.
func (l *Listener) registerRoutes(mux *http.ServeMux) {
	h := l.handlers
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
		row, err := h.Create(r.Context(), conn, body.toRequest())
		if err != nil {
			writeCreateError(w, err)
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
		var body destroyBody
		if err := decodeJSON(r, &body); err != nil {
			writeStatus(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := h.Destroy(r.Context(), conn, body.SessionHint); err != nil {
			writeDestroyError(w, err)
			return
		}
		writeStatus(w, http.StatusOK, "destroyed")
	})

	mux.HandleFunc("/v1alpha/revoke/one", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body revokeOneBody
		if err := decodeJSON(r, &body); err != nil {
			writeStatus(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := h.RevokeOne(r.Context(), conn, body.Key, body.Reason); err != nil {
			writeRevokeError(w, err)
			return
		}
		writeStatus(w, http.StatusOK, "revoked")
	})

	mux.HandleFunc("/v1alpha/revoke/all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body revokeAllBody
		if err := decodeJSON(r, &body); err != nil {
			writeStatus(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := h.RevokeAll(r.Context(), conn, body.Reason); err != nil {
			writeRevokeError(w, err)
			return
		}
		writeStatus(w, http.StatusOK, "deny-all engaged")
	})
}

// createBody is the minimal JSON create request. SessionHint and the runtime
// fields are HINTS; the host-attested caller is derived from the connection, never
// the body (NFR-SEC-43).
type createBody struct {
	SessionHint   string `json:"session_hint"`
	Image         string `json:"image"`
	ControlPubKey []byte `json:"control_pub_key"`
}

// toRequest maps the wire body to the in-process CreateRequest. The mount, egress,
// and resource shapes are carried as their zero values here — the minimal Phase-3
// transport drives the lifecycle path; the full wire schema fills them in a
// follow-up.
func (b createBody) toRequest() CreateRequest {
	return CreateRequest{
		SessionHint:   b.SessionHint,
		Image:         b.Image,
		ControlPubKey: b.ControlPubKey,
	}
}

// destroyBody is the minimal JSON destroy request: a session hint that ADDRESSES
// the caller's own row through the host-derived key.
type destroyBody struct {
	SessionHint string `json:"session_hint"`
}

// revokeOneBody and revokeAllBody are the minimal revoke request bodies.
type revokeOneBody struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

type revokeAllBody struct {
	Reason string `json:"reason"`
}

// sessionResponse is the minimal create success body: the host-derived key and the
// numeric lifecycle state. The container name is intentionally omitted — it is
// recorded data, never returned as addressable authority.
type sessionResponse struct {
	Key   string `json:"key"`
	State int    `json:"state"`
}

// decodeJSON decodes the request body into v, rejecting unknown fields so a typo
// in an operator request is a hard error rather than a silently ignored field. An
// empty body decodes to the zero value.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		// An empty body decodes to io.EOF; treat it as the zero value so a
		// parameterless revoke-all POST with no body succeeds.
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

// writeCreateError maps a lifecycle create error onto an HTTP status. An
// unattested caller is 401 (the host could not attest identity); any other stage
// failure is 409/refused. The body never discloses cross-tenant existence.
func writeCreateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingress.ErrUnattested) || errors.Is(err, lifecycle.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	default:
		writeStatus(w, http.StatusConflict, "create refused")
	}
}

// writeDestroyError maps a destroy error onto an HTTP status. ErrNotOwned and a
// collapsed not-found both surface as 404 so a forge attempt cannot distinguish
// "exists but not yours" from "absent".
func writeDestroyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingress.ErrUnattested) || errors.Is(err, lifecycle.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	case errors.Is(err, registry.ErrNotOwned):
		writeStatus(w, http.StatusNotFound, "session not addressable")
	default:
		writeStatus(w, http.StatusConflict, "destroy refused")
	}
}

// writeRevokeError maps a revoke error onto an HTTP status. A SOAR-unverified
// revoke is 403; an unattested caller is 401; anything else is 409.
func writeRevokeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, killswitch.ErrSOARUnverified):
		writeStatus(w, http.StatusForbidden, "soar signature unverifiable")
	case errors.Is(err, ingress.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	default:
		writeStatus(w, http.StatusConflict, "revoke refused")
	}
}
