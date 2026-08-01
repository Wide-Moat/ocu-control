// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// stubSessionReader satisfies the narrow read port so a Listener can be built with
// a MOUNTED read surface. It enumerates nothing: these tests never reach
// enumeration, they assert which route the mux resolved.
type stubSessionReader struct{}

func (stubSessionReader) EnrichedLiveSessions(context.Context) ([]state.EnrichedSessionRow, error) {
	return nil, nil
}

// matchedPattern returns the pattern http.ServeMux matched for a method+path, or the
// empty string when no handler is registered for that pair. Measured on go1.26.4:
// a path registered under a DIFFERENT method resolves to the empty pattern and a
// 405 — the same "not mounted" signal soar_fence_test relies on, here read
// per-method rather than per-path.
func matchedPattern(mux *http.ServeMux, method, path string) string {
	_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
	return pattern
}

// muxFor runs the production registration path against a fresh mux, with or
// without a read surface configured.
func muxFor(withRead bool) *http.ServeMux {
	deps := Deps{}
	if withRead {
		deps.Reader = stubSessionReader{}
	}
	mux := http.NewServeMux()
	NewListener("/unused.sock", deps).registerRoutes(mux)
	return mux
}

// TestSessionsPathIsMethodScoped pins /v1alpha/sessions as TWO method-scoped
// registrations — POST create and GET list — rather than one verbless pattern that
// switches on r.Method inside the handler body. The frozen operator-REST contract
// declares them as two operations (createSession, listSessions), so the mounted
// shape and the contract agree here, and a consumer can pin the read half by its own
// pattern.
//
// The load-bearing assertion is the GET half in the NO-read world. A verbless
// registration mounts the identical pattern whether or not a read surface exists, so
// the mounted route (and the source literal that spells it) vouches for a read
// surface that may be entirely absent. Method-scoped, the absence is observable: the
// GET pattern is empty when no reader is configured and carries its own name when
// one is.
func TestSessionsPathIsMethodScoped(t *testing.T) {
	t.Run("create is mounted under its own verb", func(t *testing.T) {
		for _, withRead := range []bool{false, true} {
			got := matchedPattern(muxFor(withRead), http.MethodPost, "/v1alpha/sessions")
			if got != "POST /v1alpha/sessions" {
				t.Errorf("POST /v1alpha/sessions (read surface configured=%v) matched pattern %q, want %q",
					withRead, got, "POST /v1alpha/sessions")
			}
		}
	})

	t.Run("list is mounted only with a read surface", func(t *testing.T) {
		if got := matchedPattern(muxFor(true), http.MethodGet, "/v1alpha/sessions"); got != "GET /v1alpha/sessions" {
			t.Errorf("with a reader configured, GET /v1alpha/sessions matched pattern %q, want %q",
				got, "GET /v1alpha/sessions")
		}
		if got := matchedPattern(muxFor(false), http.MethodGet, "/v1alpha/sessions"); got != "" {
			t.Errorf("with NO reader configured, GET /v1alpha/sessions matched pattern %q, want no mounted "+
				"pattern: an unmounted read surface must be observable, not hidden behind a verbless route", got)
		}
	})

	t.Run("no reader is still 405, now with the Allow header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		muxFor(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1alpha/sessions", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /v1alpha/sessions with no reader = %d, want 405 (the contract before the split)", rec.Code)
		}
		// RFC 9110 requires Allow on a 405. The hand-rolled branch this replaces
		// never set it; the mux does, so the refusal is more correct, not less.
		if allow := rec.Header().Get("Allow"); allow != "POST" {
			t.Errorf("405 Allow header = %q, want %q", allow, "POST")
		}
	})

	t.Run("with a reader the GET reaches the read surface, not create", func(t *testing.T) {
		rec := httptest.NewRecorder()
		muxFor(true).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1alpha/sessions", nil))
		// An httptest request carries no host-attested ConnInfo, so the read
		// surface's attestation gate refuses it: 401, never 405. That distinguishes
		// "the list handler ran and refused" from "no list route exists".
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET /v1alpha/sessions with a reader = %d, want 401 from the read surface's attestation gate", rec.Code)
		}
	})
}
