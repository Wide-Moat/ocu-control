// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The gateway route table decides the HTTP method in ONE place: the mux pattern.
// The two tests below are the enforcement, and both are UNIVERSAL NEGATIVES rather
// than lists of known routes — a list silently stops covering the fifth route
// somebody adds, while a negative has nothing to fall out of date. Together they
// close the class from both sides: one forbids mounting a path without its verb,
// the other forbids answering the method question inside a handler body.
//
// This is the same pair the operator package carries. It is duplicated rather than
// shared because each package must be able to fail on its own source: a guard that
// lived in one package and reached across would go quiet the moment the other
// package moved, and a gate that can go quiet without failing is the thing these
// tests exist to prevent.
//
// Why it matters here beyond tidiness. A verbless mount admits EVERY method into
// the handler, so the route table no longer describes what the route serves — on
// this listener that is the service-identity surface, where a request arrives with
// a verified SAN and no operator authority. And the hand-rolled refusal that
// compensates answers 405 without the Allow header RFC 9110 requires on that
// status.

// TestEveryMountedPatternCarriesItsVerb asserts that NO pattern registerRoutes
// mounts is verbless, reading the patterns from the package source so it covers
// whatever registerRoutes mounts today — including a route added after this test was
// written, which is the point of asserting the negative.
func TestEveryMountedPatternCarriesItsVerb(t *testing.T) {
	for pattern := range registerRoutesPatterns(t) {
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
// It scans the package's production files, so it also covers a refusal moved into a
// shared helper — which a scan scoped to the route table would miss.
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

// TestGatewayMethodRefusalCarriesAllow drives the production registration path and
// asserts the mux refuses a wrong method with 405 AND names the served verb, for
// every route registerRoutes mounts. It reads the route list from the source rather
// than a literal list here, for the same reason as the negatives above.
func TestGatewayMethodRefusalCarriesAllow(t *testing.T) {
	mux := http.NewServeMux()
	(&Listener{handlers: &Handlers{}}).registerRoutes(mux)

	probed := 0
	for pattern := range registerRoutesPatterns(t) {
		method, path, found := strings.Cut(pattern, " ")
		if !found {
			continue // the verb-carrying negative above already reports this
		}
		probed++
		// Probe with a method the route does NOT serve.
		probe := http.MethodGet
		if method == http.MethodGet {
			probe = http.MethodPost
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(probe, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", probe, path, rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != method {
			t.Errorf("%s %s: Allow = %q, want %q: a 405 must name the verb the path does serve", probe, path, allow, method)
		}
	}
	// Anti-vacuity: every route skipped as verbless would leave this test asserting
	// nothing while still reporting PASS — a gate that guards nothing. Fail instead,
	// so the green here always means routes were actually probed.
	if probed == 0 {
		t.Fatal("probed no route: every mounted pattern is verbless, so this test asserted nothing. " +
			"It must not pass vacuously — fix the mounts the verb-carrying negative reports.")
	}
}

// registerRoutesPatterns AST-scans the package for every mux.HandleFunc(<pattern>, …)
// call inside registerRoutes and returns the set of first-argument string literals.
func registerRoutesPatterns(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	_, files := parsePackageFilesWithFset(t)
	for _, file := range files {
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
				out[strings.Trim(lit.Value, `"`)] = true
				return true
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no registerRoutes HandleFunc patterns; the AST walk is broken")
	}
	return out
}

// parsePackageFilesWithFset parses every non-test .go file in this package's
// directory and returns them with the FileSet, so a guard can report a file:line
// position rather than only the fact that something is wrong somewhere.
func parsePackageFilesWithFset(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("parsed no package .go files; the AST walk is broken")
	}
	return fset, files
}
