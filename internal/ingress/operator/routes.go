// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// registerRoutes mounts the minimal operator HTTP surface onto mux: create,
// destroy, the two revoke verbs, and the resume verb (the in-band lift of the
// deployment-wide DENY-ALL). Each handler pulls the per-connection
// host-attested ConnInfo the ConnContext hook stashed and drives the matching
// Handlers method, so the transport reuses the exact in-process surface the tests
// drive directly. The bodies are a minimal JSON shape sufficient to exercise
// create→destroy and the kill-switch end-to-end; the full operator-REST wire is a
// follow-up. This is the operator plane ONLY — none of these routes is ever
// mounted on the gateway listener.
func (l *Listener) registerRoutes(mux *http.ServeMux) {
	h := l.handlers
	mux.HandleFunc("/v1alpha/sessions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			conn := connInfoFromRequest(r)
			var body createBody
			if err := decodeJSON(w, r, &body); err != nil {
				writeDecodeError(w, err)
				return
			}
			req, err := body.toRequest()
			if err != nil {
				// A malformed mount_intent is an invalid argument: deny -> 400,
				// refused before any host state (no admission, quota, or reserve).
				writeStatus(w, http.StatusBadRequest, err.Error())
				return
			}
			row, err := h.Create(r.Context(), conn, req)
			if err != nil {
				writeCreateError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, sessionResponse{Key: row.Key, State: int(row.State)})
		case http.MethodGet:
			// GET is the admin list endpoint, but only when a read surface is
			// mounted. Without one the route is POST-only, so GET is 405 (method not
			// allowed) — the same contract as before the read surface existed.
			if l.read == nil {
				writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			l.handleListSessions(w, r)
		default:
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})

	// Method-scoped so the literal /v1alpha/sessions/destroy segment is more
	// specific than the read surface's GET /v1alpha/sessions/{key} wildcard and the
	// two cannot conflict. A non-POST request to this path is 405 (now from the mux
	// pattern rather than the handler body, same observable result).
	mux.HandleFunc("POST /v1alpha/sessions/destroy", func(w http.ResponseWriter, r *http.Request) {
		conn := connInfoFromRequest(r)
		var body destroyBody
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
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
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
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
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
			return
		}
		if err := h.RevokeAll(r.Context(), conn, body.Reason); err != nil {
			writeRevokeError(w, err)
			return
		}
		writeStatus(w, http.StatusOK, "deny-all engaged")
	})

	mux.HandleFunc("/v1alpha/resume/all", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body resumeAllBody
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
			return
		}
		if err := h.ResumeAll(r.Context(), conn, body.Reason); err != nil {
			writeRevokeError(w, err)
			return
		}
		writeStatus(w, http.StatusOK, "deny-all lifted")
	})

	// The mcp-key operator surface (ADR-0027) mints and revokes the sk-ocu- MCP
	// API keys. Both are POST-only on the operator plane ONLY — never mounted on
	// the gateway listener (NFR-SEC-52). The literal /revoke segment outranks the
	// bare create path so the two cannot conflict. The caller is host-attested from
	// SO_PEERCRED inside the handler; no body field carries the acting identity.
	mux.HandleFunc("POST /v1alpha/mcp-keys", func(w http.ResponseWriter, r *http.Request) {
		conn := connInfoFromRequest(r)
		var body mcpKeyCreateBody
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
			return
		}
		sk, rec, err := h.MCPKeyCreate(r.Context(), conn, body.Tenant, body.Deployment, body.ExpiresAt)
		if err != nil {
			writeMCPKeyError(w, err)
			return
		}
		// Reveal the raw key exactly once here, for the shown-once CLI render. The
		// SecretKey redacts on every other surface; this is the single escape hatch,
		// mirroring the occ create-response contract.
		writeJSON(w, http.StatusCreated, mcpKeyCreateResponse{
			RawKey: sk.Reveal(),
			KeyID:  rec.KeyID,
			Tenant: rec.Tenant,
		})
	})

	mux.HandleFunc("POST /v1alpha/mcp-keys/revoke", func(w http.ResponseWriter, r *http.Request) {
		conn := connInfoFromRequest(r)
		var body mcpKeyRevokeBody
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
			return
		}
		outcome, err := h.MCPKeyRevoke(r.Context(), conn, body.KeyID, body.Reason)
		if err != nil {
			writeMCPKeyError(w, err)
			return
		}
		if outcome.DenyAllPending {
			// The revoke succeeded and removed the LAST active key. It is a 200, not
			// an error — but the operator MUST know the live gateway does not yet
			// converge to deny-all (the config plane has no empty-set representation;
			// open-computer-use#332), so the just-revoked key may keep validating
			// until the gateway restarts.
			writeStatus(w, http.StatusOK, "revoked; WARNING: last active key revoked — "+
				"deny-all is not yet propagated to a live gateway (config-plane deny-all-artifact contract pending, open-computer-use#332); "+
				"the revoked key may keep validating until the gateway restarts")
			return
		}
		writeStatus(w, http.StatusOK, "revoked")
	})

	// The admin read-surface (ADR-0022) is mounted only when a reader was supplied.
	// These are GET-only, read-only, and reach ONLY the ReadHandlers (which holds no
	// seam and no mutating surface) — never the mutating Handlers above. The
	// per-key route uses a method+path pattern so it cannot shadow the literal
	// /v1alpha/sessions/destroy POST (a literal segment outranks the {key} wildcard,
	// and the methods differ regardless).
	if l.read != nil {
		mux.HandleFunc("GET /v1alpha/sessions/{key}", l.handleGetSession)
		mux.HandleFunc("GET /v1alpha/deployment", l.handleDeployment)
	}
}

// handleListSessions serves GET /v1alpha/sessions. It parses the optional
// ?include_released flag and returns the live session views. An unattested caller
// is 401; a store/enumeration failure is 503; success is 200 with a JSON array.
func (l *Listener) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if l.read == nil {
		writeStatus(w, http.StatusNotFound, "read surface not configured")
		return
	}
	includeReleased := r.URL.Query().Get("include_released") == "true"
	conn := connInfoFromRequest(r)
	views, err := l.read.ListSessions(r.Context(), conn, includeReleased)
	if err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

// handleGetSession serves GET /v1alpha/sessions/{key}. A missing key is 404
// (uniform across released/absent); an unattested caller is 401; a store failure
// is 503.
func (l *Listener) handleGetSession(w http.ResponseWriter, r *http.Request) {
	if l.read == nil {
		writeStatus(w, http.StatusNotFound, "read surface not configured")
		return
	}
	key := r.PathValue("key")
	conn := connInfoFromRequest(r)
	view, err := l.read.GetSession(r.Context(), conn, key)
	if err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleDeployment serves GET /v1alpha/deployment: the two deployment-wide
// singletons. An unattested caller is 401; success is 200.
func (l *Listener) handleDeployment(w http.ResponseWriter, r *http.Request) {
	if l.read == nil {
		writeStatus(w, http.StatusNotFound, "read surface not configured")
		return
	}
	conn := connInfoFromRequest(r)
	view, err := l.read.Deployment(r.Context(), conn)
	if err != nil {
		writeReadError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// writeReadError maps a read-surface error onto an HTTP status. An unattested
// caller is 401; a not-found key is 404; a store/enumeration failure is 503
// (Denied/unavailable — the read surface never serves a partial or guessed view).
func writeReadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingress.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	case errors.Is(err, ErrSessionNotFound):
		writeStatus(w, http.StatusNotFound, "session not found")
	case errors.Is(err, state.ErrStoreUnavailable), errors.Is(err, registry.ErrEnumerationUnsupported):
		writeStatus(w, http.StatusServiceUnavailable, "read surface unavailable")
	default:
		writeStatus(w, http.StatusServiceUnavailable, "read surface unavailable")
	}
}

// createBody is the minimal JSON create request. SessionHint and the runtime
// fields are HINTS; the host-attested caller is derived from the connection, never
// the body (NFR-SEC-43).
type createBody struct {
	SessionHint   string           `json:"session_hint"`
	Image         string           `json:"image"`
	ControlPubKey []byte           `json:"control_pub_key"`
	MountIntent   *mountIntentBody `json:"mount_intent"`
}

// mountIntentBody is the wire shape of the per-session storage mount intent,
// field names per the frozen session_setup.proto MountIntent. It carries NO
// auth_token field: the Storage-JWT is minted host-side and rides the F7
// mount-config push, never a create body (custody) — the strict decoder refuses
// a smuggled credential field as unknown.
type mountIntentBody struct {
	Destination    string `json:"destination"`
	FilesystemID   string `json:"filesystem_id"`
	MemoryStoreID  string `json:"memory_store_id"`
	ReadOnly       bool   `json:"read_only"`
	CacheDurationS uint32 `json:"cache_duration_s"`
}

// The wire-level refusals for a PRESENT mount_intent, mirroring the published
// contract shape: exactly one scope id (both AND neither are malformed — an
// ABSENT mount_intent is the legitimate no-scope compute/exec session,
// ADR-0017), an absolute guest destination, and the 256-char scope-id cap
// (utf8.RuneCountInString, the same rune-count rule the mcp-key tenant cap
// uses). Each is a deny -> 400 invalid argument at decode, before any host
// state exists.
var (
	errMountScopeConflict = errors.New("mount_intent: exactly one of filesystem_id / memory_store_id")
	errMountDestRelative  = errors.New("mount_intent: destination must be an absolute guest path")
	errMountFSIDTooLong   = errors.New("mount_intent: filesystem_id exceeds 256 characters")
	errMountMemIDTooLong  = errors.New("mount_intent: memory_store_id exceeds 256 characters")
)

// scopeIDMaxRunes caps the mount scope ids on the wire.
const scopeIDMaxRunes = 256

// validate checks a present mount_intent against the wire contract.
func (m *mountIntentBody) validate() error {
	if (m.FilesystemID != "") == (m.MemoryStoreID != "") { // both set or neither set
		return errMountScopeConflict
	}
	if !strings.HasPrefix(m.Destination, "/") {
		return errMountDestRelative
	}
	if utf8.RuneCountInString(m.FilesystemID) > scopeIDMaxRunes {
		return errMountFSIDTooLong
	}
	if utf8.RuneCountInString(m.MemoryStoreID) > scopeIDMaxRunes {
		return errMountMemIDTooLong
	}
	return nil
}

// toRequest maps the wire body to the in-process CreateRequest. The egress and
// resource shapes are carried as their zero values here — the full wire schema
// fills them in a follow-up. The mount intent maps field-for-field; its
// AuthToken is never populated from the wire (custody).
func (b createBody) toRequest() (CreateRequest, error) {
	req := CreateRequest{
		SessionHint:   b.SessionHint,
		Image:         b.Image,
		ControlPubKey: b.ControlPubKey,
	}
	if b.MountIntent == nil {
		return req, nil
	}
	if err := b.MountIntent.validate(); err != nil {
		return CreateRequest{}, err
	}
	req.Mount = runtime.MountIntent{
		Destination:   b.MountIntent.Destination,
		FilesystemID:  b.MountIntent.FilesystemID,
		MemoryStoreID: b.MountIntent.MemoryStoreID,
		ReadOnly:      b.MountIntent.ReadOnly,
		CacheSeconds:  int(b.MountIntent.CacheDurationS),
	}
	return req, nil
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

// resumeAllBody is the minimal resume request body: the operator-supplied reason
// for the in-band lift of the deployment-wide DENY-ALL. An empty body decodes to
// the zero value (an empty reason), exactly like revoke/all.
type resumeAllBody struct {
	Reason string `json:"reason"`
}

// sessionResponse is the minimal create success body: the host-derived key and the
// numeric lifecycle state. The container name is intentionally omitted — it is
// recorded data, never returned as addressable authority.
type sessionResponse struct {
	Key   string `json:"key"`
	State int    `json:"state"`
}

// mcpKeyCreateBody is the mcp-key create request. Tenant and Deployment are the
// operator-supplied SCOPE of the new key (legitimate operator input — the
// operator chooses which tenant/deployment the key serves, distinct from the
// NFR-SEC-43 caller-identity rule). ExpiresAt is optional: nil means a
// non-expiring key (ADR-0027 §Storage). No field carries the acting caller's
// identity — that is derived from SO_PEERCRED in the handler.
type mcpKeyCreateBody struct {
	Tenant     string     `json:"tenant"`
	Deployment string     `json:"deployment,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// mcpKeyCreateResponse is the mcp-key create success body. RawKey is the
// shown-once sk-ocu- key (Reveal() was called in the route handler); the CLI
// prints it once and it is never served again. KeyID is the public handle for a
// subsequent revoke --id.
type mcpKeyCreateResponse struct {
	RawKey string `json:"raw_key"`
	KeyID  string `json:"key_id"`
	Tenant string `json:"tenant"`
}

// mcpKeyRevokeBody is the mcp-key revoke request: the public key_id handle and an
// operator-supplied reason for the audit trail.
type mcpKeyRevokeBody struct {
	KeyID  string `json:"key_id"`
	Reason string `json:"reason,omitempty"`
}

// maxBodyBytes caps the request body the operator decode admits before the
// decoder is refused — a pre-auth memory / slow-body guard. 64KiB mirrors the
// control-RPC frame cap; the operator bodies are small JSON. An oversized body
// is short-circuited at the cap (never read whole into memory) and surfaces a
// *http.MaxBytesError the caller maps to 413.
const maxBodyBytes = 64 << 10

// decodeJSON decodes the request body into v, rejecting unknown fields so a typo
// in an operator request is a hard error rather than a silently ignored field. An
// empty body decodes to the zero value. The body is wrapped in a MaxBytesReader so
// an oversized body is refused at the cap rather than read whole into memory; on
// that path Decode returns a *http.MaxBytesError the caller maps to 413.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	// Wrap BEFORE constructing the decoder so the decoder can pull at most
	// maxBodyBytes+1; the nil-body guard above stays first so a nil body is never
	// wrapped and still decodes to the zero value.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
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

// writeDecodeError maps a decode error onto an HTTP status: an oversized body is
// the honest 413 Request Entity Too Large, every other malformed/unknown-field
// body stays the 400 the call sites already returned.
func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeStatus(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeStatus(w, http.StatusBadRequest, "invalid request body")
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

// writeMCPKeyError maps an mcp-key create/revoke error onto an HTTP status. An
// unattested caller is 401. A ErrScopeInvalid (the runtime backstop to the
// compile-time operator-only seal) is 403 — a call reached the engine without a
// genuine operator scope. Every other failure (mint, audit-emit deny, store,
// re-render) is a fail-closed 503: the action did NOT take effect, and the body
// discloses nothing about the internal cause. The audit-first engine guarantees
// no durable mutation was acknowledged when any of these fire.
func writeMCPKeyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingress.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	case errors.Is(err, mcpkey.ErrScopeInvalid):
		writeStatus(w, http.StatusForbidden, "operator scope required")
	case errors.Is(err, mcpkey.ErrTenantMissing), errors.Is(err, mcpkey.ErrDeploymentMissing):
		// The canon create-request marks both required; an empty value would mint
		// a record the published A2 artifact cannot legally render (minLength 1).
		writeStatus(w, http.StatusBadRequest, "tenant and deployment are required")
	case errors.Is(err, mcpkey.ErrTenantTooLong), errors.Is(err, mcpkey.ErrDeploymentTooLong):
		// The over-long half of the same constraint: the A2 artifact pins both
		// fields at maxLength 256, so an over-long value is a client error (400),
		// not an internal fault.
		writeStatus(w, http.StatusBadRequest, "tenant and deployment must not exceed the maximum length")
	default:
		writeStatus(w, http.StatusServiceUnavailable, "mcp-key operation refused")
	}
}
