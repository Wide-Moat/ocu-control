// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"go/ast"
	"strings"
	"testing"
)

// The operator route table decides the HTTP method in ONE place: the mux pattern.
// The two tests below are the enforcement, and both are UNIVERSAL NEGATIVES rather
// than lists of known routes — a list silently stops covering the fourth route
// somebody adds, while a negative has nothing to fall out of date. Together they
// close the class from both sides: one forbids mounting a path without its verb,
// the other forbids answering the method question inside a handler body.
//
// Why the pair matters beyond tidiness. A verbless mount accepts EVERY method into
// the handler, so the route table no longer describes what the route serves, and the
// hand-rolled refusal that compensates answers 405 without the Allow header RFC 9110
// requires on that status. Method-scoped, the mux refuses the wrong method before any
// handler code runs and names the served verb in Allow.

// TestEveryMountedPatternCarriesItsVerb asserts that NO pattern registerRoutes mounts
// is verbless. It reads the patterns from the same AST scan the exact-set fence uses,
// so it covers whatever registerRoutes mounts today — including a route added after
// this test was written, which is the whole point of asserting the negative.
func TestEveryMountedPatternCarriesItsVerb(t *testing.T) {
	patterns := registerRoutesPatterns(t)
	for pattern := range patterns {
		method, rest, found := strings.Cut(pattern, " ")
		if !found || !isHTTPMethodToken(method) || !strings.HasPrefix(rest, "/") {
			t.Errorf("registerRoutes mounts %q without a method in the pattern: a verbless mount admits EVERY "+
				"method into the handler, so the route table stops describing what the route serves and the "+
				"handler has to hand-roll the refusal. Mount it as \"<METHOD> %s\" instead.", pattern, pattern)
		}
	}
}

// isHTTPMethodToken reports whether tok is one of the request methods this surface
// mounts. It is a closed set on purpose: a lowercase or misspelled method in a
// pattern is not a verb-scoped route, it is a route mounted on a HOST named "post"
// (the pattern grammar reads an unrecognised leading token as part of the host), so
// accepting any all-caps word would let that mistake pass as verb-scoped.
func isHTTPMethodToken(tok string) bool {
	switch tok {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// TestNoHandRolledMethodNotAllowed asserts that no production file in this package
// writes an http.StatusMethodNotAllowed of its own. With every route method-scoped
// the mux produces the 405 itself, together with the Allow header; a hand-rolled one
// is therefore both redundant and, because it sets no Allow, a response that does not
// meet RFC 9110 for that status.
//
// It scans the package's production files (parsePackageFiles excludes _test.go), so
// it also covers a helper outside registerRoutes — a refusal moved into a shared
// writeX function would evade a scan scoped to the route table.
func TestNoHandRolledMethodNotAllowed(t *testing.T) {
	fset, files := parsePackageFilesWithFset(t)
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "StatusMethodNotAllowed" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "http" {
				return true
			}
			t.Errorf("%s hand-rolls http.StatusMethodNotAllowed: this route decides the method inside the "+
				"handler body. Mount the route with its verb in the mux pattern instead — the mux then answers "+
				"405 before the handler runs and supplies the Allow header RFC 9110 requires on that status.",
				fset.Position(sel.Pos()))
			return true
		})
	}
}
