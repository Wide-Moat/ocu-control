// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"go/ast"
	"testing"
)

// expectedMountedRoutes is the COMPLETE set of route patterns registerRoutes
// mounts — the unconditional operator surface plus the two conditional read routes.
// It is the exact-set the fence enforces: registerRoutes must mount THESE and no
// others. Adding a new route to registerRoutes without adding it here fails the
// build, so a new privileged mount cannot slip in unreviewed — including one that
// re-uses an already-mounted handler on a NEW path (the case the soar_fence
// positive-pin and the deferred-handler allow-list both miss, because one checks a
// fixed path list and the other keys on the handler method, not the path).
//
// /healthz and GET /metrics are intentionally absent: they are mounted in Serve,
// not registerRoutes, so this is precisely the registerRoutes surface (matching the
// scope soar_fence_test documents).
var expectedMountedRoutes = map[string]bool{
	"/v1alpha/sessions":              true,
	"POST /v1alpha/sessions/destroy": true,
	"/v1alpha/revoke/one":            true,
	"/v1alpha/revoke/all":            true,
	"/v1alpha/resume/all":            true,
	"POST /v1alpha/mcp-keys":         true,
	"POST /v1alpha/mcp-keys/revoke":  true,
	// Conditional on a configured read surface (l.read != nil), but statically
	// present in registerRoutes, so the AST scan sees them regardless of runtime.
	"GET /v1alpha/sessions/{key}": true,
	"GET /v1alpha/deployment":     true,
}

// TestRegisterRoutesMountsExactlyTheExpectedSet is the exact-set fence on the
// mounted operator route table. It AST-scans registerRoutes for every mux.HandleFunc
// pattern literal and asserts the set equals expectedMountedRoutes — both directions:
// a NEW mounted route not in the expected set fails, and a removed route (a pattern
// in the expected set no longer mounted) fails.
//
// This closes the gap the finder surfaced: soar_fence_test's positive pin iterates a
// fixed list of 5 known paths and so cannot see a 6th, and TestDeferredHandlers keys
// on the handler METHOD, so a new PATH re-invoking an already-mounted handler (e.g. a
// second route calling h.RevokeAll) evades both. Keying on the PATH literal catches
// any new route regardless of which handler it drives.
func TestRegisterRoutesMountsExactlyTheExpectedSet(t *testing.T) {
	got := registerRoutesPatterns(t)

	for pattern := range got {
		if !expectedMountedRoutes[pattern] {
			t.Errorf("registerRoutes mounts %q, which is not in expectedMountedRoutes: a new operator route was added "+
				"without recording it here. If the mount is deliberate, add the pattern to expectedMountedRoutes (and "+
				"confirm it is not a privileged route that should be gated on a wire contract).", pattern)
		}
	}
	for pattern := range expectedMountedRoutes {
		if !got[pattern] {
			t.Errorf("expectedMountedRoutes lists %q but registerRoutes no longer mounts it: a route was removed or "+
				"renamed. Update expectedMountedRoutes if the change is deliberate.", pattern)
		}
	}
}

// registerRoutesPatterns AST-scans the package for every mux.HandleFunc(<pattern>, …)
// call inside the registerRoutes method and returns the set of first-argument string
// literals (the route patterns). It scopes to registerRoutes specifically so the
// healthz/metrics mounts in Serve are out of scope, matching expectedMountedRoutes.
func registerRoutesPatterns(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, file := range parsePackageFiles(t) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "registerRoutes" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "HandleFunc" || len(call.Args) == 0 {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok {
					return true
				}
				// Strip the surrounding quotes from the string literal.
				out[unquoteLiteral(lit.Value)] = true
				return true
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no registerRoutes HandleFunc patterns; the AST walk is broken")
	}
	return out
}

// unquoteLiteral strips the surrounding double quotes from a Go string literal token
// (e.g. `"POST /v1alpha/mcp-keys"` -> `POST /v1alpha/mcp-keys`). The route patterns
// are plain interpreted strings with no escapes, so a simple trim is sufficient and
// avoids pulling in strconv for a single unquote.
func unquoteLiteral(tok string) string {
	if len(tok) >= 2 && tok[0] == '"' && tok[len(tok)-1] == '"' {
		return tok[1 : len(tok)-1]
	}
	return tok
}
