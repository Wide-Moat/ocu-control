// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// readHeaderTimeout bounds how long the gateway server waits for a request's
// headers, closing a connection that dribbles them (a Slowloris guard). The
// gateway plane faces in-workforce services, so the bound matters here; it also
// keeps gosec satisfied that no header read is unbounded.
const readHeaderTimeout = 10 * time.Second

// readTimeout bounds the whole-request read (headers plus body), defeating a slow
// body that dribbles bytes under the header timeout. 30s suits a gateway service
// surface (small JSON, not bulk data) without breaking a legitimate slow client
// on a real network.
const readTimeout = 30 * time.Second

// idleTimeout bounds an idle keep-alive connection so a parked socket is reaped
// rather than held open indefinitely.
const idleTimeout = 120 * time.Second

// maxBodyBytes caps the request body the gateway decode admits before the decoder
// is refused — a pre-auth memory / slow-body guard. 64KiB mirrors the control-RPC
// frame cap; the gateway bodies are small JSON. An oversized body is short-
// circuited at the cap (never read whole into memory) and surfaces a
// *http.MaxBytesError the caller maps to 413.
const maxBodyBytes = 64 << 10

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

	srv := newServer(ctx, mux)

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

// newServer builds the gateway HTTP server with the bounded read/idle posture and
// the per-connection channel-marking ConnContext hook. It is factored out of Serve
// so the timeout wiring is unit-observable: the read header, whole-request read, and
// idle bounds are all non-zero and assertable on the returned *http.Server.
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
		row, err := h.Create(r.Context(), scope, conn, req)
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
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
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
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
			return
		}
		row, err := h.Status(r.Context(), scope, conn, body.SessionHint)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, sessionResponse{Key: row.Key, State: int(row.State)})
	})

	mux.HandleFunc("/v1alpha/sessions/exec", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeStatus(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		conn := connInfoFromRequest(r)
		var body execBody
		if err := decodeJSON(w, r, &body); err != nil {
			writeDecodeError(w, err)
			return
		}
		req, err := body.toExecRequest()
		if err != nil {
			// A malformed exec body (empty argv, bad base64 stdin) is an invalid
			// argument: deny -> 400, refused before the row lookup and the driver.
			writeStatus(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := h.Exec(r.Context(), scope, conn, body.SessionHint, req)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, execResponse{
			ExitCode:        res.ExitCode,
			StdoutB64:       base64.StdEncoding.EncodeToString(res.Stdout),
			StderrB64:       base64.StdEncoding.EncodeToString(res.Stderr),
			StdoutTruncated: res.StdoutTruncated,
			StderrTruncated: res.StderrTruncated,
		})
	})
}

// execBody is the gateway exec request: the addressed session hint plus the
// command and its optional environment, working directory, base64 stdin, and
// timeout. The hint ADDRESSES the caller's own row (NFR-SEC-43); no field carries
// identity or a credential.
type execBody struct {
	SessionHint string            `json:"session_hint"`
	Argv        []string          `json:"argv"`
	Env         map[string]string `json:"env"`
	Cwd         string            `json:"cwd"`
	StdinB64    string            `json:"stdin_b64"`
	TimeoutS    uint32            `json:"timeout_s"`
}

// errExecEmptyArgv is the wire refusal for a missing command.
var errExecEmptyArgv = errors.New("exec: argv must be non-empty")

// toExecRequest validates and maps the wire body to the in-process ExecRequest:
// argv must be non-empty and stdin_b64 must decode, each a deny -> 400 before the
// row lookup. Stdin rides base64 (a []byte on the wire), never a credential.
func (b execBody) toExecRequest() (lifecycle.ExecRequest, error) {
	if len(b.Argv) == 0 || b.Argv[0] == "" {
		return lifecycle.ExecRequest{}, errExecEmptyArgv
	}
	var stdin []byte
	if b.StdinB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(b.StdinB64)
		if err != nil {
			return lifecycle.ExecRequest{}, fmt.Errorf("exec: stdin_b64 is not valid base64: %w", err)
		}
		stdin = decoded
	}
	return lifecycle.ExecRequest{
		Argv:     b.Argv,
		Env:      b.Env,
		Cwd:      b.Cwd,
		Stdin:    stdin,
		TimeoutS: b.TimeoutS,
	}, nil
}

// execResponse is the gateway exec result: the guest child's exit code and the
// captured, per-stream-bounded output as base64, with the truncation flags.
type execResponse struct {
	ExitCode        uint8  `json:"exit_code"`
	StdoutB64       string `json:"stdout_b64"`
	StderrB64       string `json:"stderr_b64"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// createBody is the minimal JSON create request. SessionHint and the runtime
// fields are HINTS; the host-attested caller is derived from the verified SAN,
// never the body (NFR-SEC-43).
type createBody struct {
	SessionHint string `json:"session_hint"`
	Image       string `json:"image"`
	// MountIntent is the LEGACY singular mount shape; it maps to a one-element
	// list. MountIntents supersedes it (the ADR-0029 two-mount layout); a body
	// setting BOTH is ambiguous and refused.
	MountIntent  *mountIntentBody   `json:"mount_intent"`
	MountIntents []mountIntentBody  `json:"mount_intents"`
	EgressPolicy *egressPolicyBody  `json:"egress_policy"`
}

// egressPolicyBody is the wire shape of the per-session egress trust-edge policy,
// field names per the frozen session_setup.proto EgressPolicy. default_deny is the
// posture (true on every production path); allowed_upstream is the single
// allow-listed object-store the mount client may dial guest-out; filesystem_id
// binds the egress to the same scope as the mount. The strict decoder refuses any
// smuggled field (e.g. a credential) as unknown.
type egressPolicyBody struct {
	DefaultDeny     bool   `json:"default_deny"`
	AllowedUpstream string `json:"allowed_upstream"`
	FilesystemID    string `json:"filesystem_id"`
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
	errMountScopeConflict  = errors.New("mount_intent: exactly one of filesystem_id / memory_store_id")
	errMountShapesConflict = errors.New("mount_intent and mount_intents are mutually exclusive; use mount_intents")
	errMountDupDestination = errors.New("mount_intents: duplicate destination")
	errMountListOverCap    = errors.New("mount_intents: too many mounts")
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

// toRequest maps the wire body to the in-process CreateRequest. The mount intent
// and egress policy map field-for-field; the mount AuthToken is never populated
// from the wire (custody).
func (b createBody) toRequest() (CreateRequest, error) {
	req := CreateRequest{
		SessionHint: b.SessionHint,
		Image:       b.Image,
	}
	if b.EgressPolicy != nil {
		req.Egress = runtime.EgressPolicy{
			DefaultDeny:     b.EgressPolicy.DefaultDeny,
			AllowedUpstream: b.EgressPolicy.AllowedUpstream,
			FilesystemID:    b.EgressPolicy.FilesystemID,
		}
	}
	mounts, err := resolveMountBodies(b.MountIntent, b.MountIntents)
	if err != nil {
		return CreateRequest{}, err
	}
	req.Mounts = mounts
	return req, nil
}

// maxMountIntents caps the per-session mount list: two is the shipped layout
// (uploads RO + outputs RW), four leaves additive room without letting a caller
// provision an unbounded mount fan-out.
const maxMountIntents = 4

// resolveMountBodies folds the singular-vs-plural mount fields into one
// validated list. The shapes are mutually exclusive (both set is ambiguous and
// refused); the legacy singular maps to a one-element list; each entry is
// validated like the singular always was, plus list-level rules: bounded count
// and pairwise-distinct destinations (two mounts on one mountpoint would shadow
// each other in the guest).
func resolveMountBodies(single *mountIntentBody, plural []mountIntentBody) ([]runtime.MountIntent, error) {
	if single != nil && len(plural) > 0 {
		return nil, errMountShapesConflict
	}
	entries := plural
	if single != nil {
		entries = []mountIntentBody{*single}
	}
	if len(entries) > maxMountIntents {
		return nil, errMountListOverCap
	}
	seen := make(map[string]struct{}, len(entries))
	mounts := make([]runtime.MountIntent, 0, len(entries))
	for i := range entries {
		e := entries[i]
		if err := e.validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[e.Destination]; dup {
			return nil, errMountDupDestination
		}
		seen[e.Destination] = struct{}{}
		mounts = append(mounts, runtime.MountIntent{
			Destination:   e.Destination,
			FilesystemID:  e.FilesystemID,
			MemoryStoreID: e.MemoryStoreID,
			ReadOnly:      e.ReadOnly,
			CacheSeconds:  int(e.CacheDurationS),
		})
	}
	return mounts, nil
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
// body decodes to the zero value. The body is wrapped in a MaxBytesReader so an
// oversized body is refused at the cap rather than read whole into memory; on that
// path Decode returns a *http.MaxBytesError the caller maps to 413.
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

// writeServiceError maps a service error onto an HTTP status without disclosing
// cross-tenant existence. An unattested caller is 401; ErrNotOwned and a collapsed
// not-found are both 404 (indistinguishable); any other refusal is 409.
func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ingress.ErrUnattested) || errors.Is(err, lifecycle.ErrUnattested):
		writeStatus(w, http.StatusUnauthorized, "caller identity unattested")
	case errors.Is(err, registry.ErrNotOwned):
		writeStatus(w, http.StatusNotFound, "session not addressable")
	case errors.Is(err, lifecycle.ErrInvalidArgument):
		// A request-derived invalid argument (e.g. no resolvable guest image) is a
		// client error: 400, same class as the toRequest() decode refusal. It is safe
		// to surface the CLASS — the Manager wraps ONLY request-derivable failures in
		// this sentinel, so no tenant state is consulted and it is never an existence
		// oracle. The body is a fixed string, never err.Error(): the Manager folds
		// caller-supplied input (e.g. the rejected image name) into the wrapped
		// message, so echoing it back would reflect attacker-controlled bytes into the
		// response (a G705 taint flow). The status code carries the class; the detail
		// stays in the server-side audit trail, not the client body.
		writeStatus(w, http.StatusBadRequest, "invalid request argument")
	default:
		writeStatus(w, http.StatusConflict, "request refused")
	}
}
