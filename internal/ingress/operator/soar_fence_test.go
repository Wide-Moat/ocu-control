// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoSOARRouteMountedBefore205 is the enforced fence on the tested-but-unmounted
// SOAR verify-then-mint handlers (RevokeOneViaSOAR / RevokeAllViaSOAR). Those
// handlers are real, proven capability, but their HTTP transport is DEFERRED: the
// mount lands together with the #205 SOAR wire (contracts/openapi/soar-revoke.openapi.yaml,
// STATUS: draft). This test runs the exact production registration path and asserts
// that no SOAR-webhook route is mounted today, so a careless future-mount BEFORE the
// #205 contract freezes turns this test RED with an actionable reason — the deferral
// is enforced, not merely documented.
//
// It is white-box (package operator) because registerRoutes is a package-private
// method on *Listener; every other operator test is black-box (package operator_test),
// so this is the package's one white-box file.
//
// The probe rides a documented, verified stdlib signal: http.ServeMux.Handler returns
// the EXACT mounted pattern for a path that has a registered handler and the EMPTY
// STRING for a path that does not. Confirmed empirically on go1.26.4; a future Go
// upgrade reviewer should re-confirm this behaviour if the test starts misbehaving.
func TestNoSOARRouteMountedBefore205(t *testing.T) {
	const fenceMsg = "a SOAR route appears to be mounted; SOAR transport is gated on the frozen #205 soar-revoke.openapi.yaml — do not mount a SOAR webhook route before that contract freezes."

	// Empty Deps{} is sufficient: registerRoutes reads only l.handlers (set by
	// NewListener via NewHandlers, which tolerates the zero Deps — the resolver
	// defaults and manager/engine/seam stay nil), and it only BINDS closures over
	// l.handlers; it never invokes a handler at registration time. So no Manager,
	// Engine, Seam, or bound socket is needed to inspect the mux. If a future refactor
	// made registerRoutes eager-call a handler at mount time, this test would need real
	// Deps.
	l := NewListener("/unused.sock", Deps{})
	mux := http.NewServeMux()
	l.registerRoutes(mux)

	// patternFor returns the pattern http.ServeMux matched for a POST to path, or the
	// empty string when no handler is registered for it.
	patternFor := func(path string) string {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, path, nil))
		return pattern
	}

	// POSITIVE pin: registerRoutes mounts EXACTLY these five operator routes. Pinning
	// the set means any NEW mount (a SOAR route or anything else) that registerRoutes
	// grows is caught here, because each known path must match its own pinned pattern.
	// The destroy route is method-scoped ("POST /v1alpha/sessions/destroy") so the
	// literal segment outranks the read surface's GET /v1alpha/sessions/{key} wildcard;
	// the probe POSTs to it, so the matched pattern carries the POST method prefix and
	// the pin reflects that exact registered shape, not a bare literal. /healthz is
	// intentionally NOT in this set — it is mounted in Serve, not in registerRoutes — so
	// this is precisely the registerRoutes surface. Do not "fix" this test by adding
	// /healthz.
	knownPatterns := []struct{ path, pattern string }{
		{"/v1alpha/sessions", "/v1alpha/sessions"},
		{"/v1alpha/sessions/destroy", "POST /v1alpha/sessions/destroy"},
		{"/v1alpha/revoke/one", "/v1alpha/revoke/one"},
		{"/v1alpha/revoke/all", "/v1alpha/revoke/all"},
		{"/v1alpha/resume/all", "/v1alpha/resume/all"},
	}
	matched := make([]string, 0, len(knownPatterns))
	for _, want := range knownPatterns {
		got := patternFor(want.path)
		if got != want.pattern {
			t.Fatalf("registerRoutes mounted set drifted: probe %q matched pattern %q, want %q", want.path, got, want.pattern)
		}
		matched = append(matched, got)
	}

	// NEGATIVE assertion (the enforced bit): none of the plausible SOAR-webhook route
	// shapes the #205 wire could mount is registered today. An empty matched pattern is
	// the verified, exact signal for "no handler mounted for this path".
	soarCandidates := []string{
		"/v1alpha/revoke/one/soar",
		"/v1alpha/revoke/all/soar",
		"/v1alpha/soar/revoke/one",
		"/v1alpha/soar/revoke/all",
		"/v1alpha/soar/revoke",
	}
	for _, path := range soarCandidates {
		if pattern := patternFor(path); pattern != "" {
			t.Fatalf("SOAR candidate %q is mounted (pattern %q): %s", path, pattern, fenceMsg)
		}
		// Record any matched pattern for the catch-all below; the empty string is
		// filtered there.
		matched = append(matched, patternFor(path))
	}

	// CATCH-ALL belt: no mounted pattern this test observed contains "soar"
	// (case-insensitive), so even a SOAR route shape outside the candidate list above
	// trips the fence the moment a known path or a candidate happens to resolve to it.
	for _, pattern := range matched {
		if pattern == "" {
			continue
		}
		if strings.Contains(strings.ToLower(pattern), "soar") {
			t.Fatalf("a mounted pattern %q names soar: %s", pattern, fenceMsg)
		}
	}
}
