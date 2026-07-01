// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// deferredHandlers is the allow-list of operator Handlers methods that are
// COMPLETE and TESTED in-process but whose HTTP route is DELIBERATELY not mounted
// yet. Each is a design-fenced operator op awaiting its wire surface, the same
// class as the SOAR-revoke pair:
//
//   - RevokeOneViaSOAR / RevokeAllViaSOAR — the SOAR-webhook revoke pair, mounted
//     when the #205 operator-REST/SOAR wire schemas land (the verify-then-mint
//     route is gated on that contract freeze).
//   - LiftDeny — the operator denylist-edit (lift a per-session deny), mounted with
//     the denylist-edit wire route.
//   - OverrideQuota — the operator quota-override, mounted with the quota-override
//     wire route.
//
// They are NOT orphans: the Engine ops they call are full audit-first fail-closed
// implementations, and each handler has attested/unattested unit tests. The Go
// dead-code analyzer flags all four as "unreachable func" only because no route
// reaches them from main; this allow-list is the machine-checked record that the
// deferral is DELIBERATE. The test below makes that a build invariant — see its doc
// for the three properties it enforces.
var deferredHandlers = map[string]bool{
	"RevokeOneViaSOAR": true,
	"RevokeAllViaSOAR": true,
	"LiftDeny":         true,
	"OverrideQuota":    true,
	// MCPKeyCreate/MCPKeyRevoke are complete and tested in-process but their HTTP
	// routes are DEFERRED, gated on the architect's canon wire-freeze (operator-REST
	// verb + Control→gateway hashed-key-set contract, Q7 of 08-RESEARCH.md). Plan
	// 08-05 mounts them after the wire-freeze checkpoint passes.
	"MCPKeyCreate": true,
	"MCPKeyRevoke": true,
}

// TestDeferredHandlers_AllowListIsExact is the enforced fence for the deliberately
// not-yet-mounted operator handlers (replacing a bare doc-comment with a machine
// check, so a future dead-code pass cannot propose deleting them and a premature
// mount cannot slip in). It parses the package source and enforces THREE properties
// against the deferredHandlers allow-list:
//
// SUPERSEDES TestNoSOARRouteMountedBefore205 (on fast-follow/class-a-hardening):
// this general invariant (unmounted == the allow-list, exactly) strictly dominates
// the SOAR-specific one — it already covers the SOAR pair plus any future deferred
// handler, so the two must not both ride into main (one fact, one source of truth).
// AT MERGE of fast-follow/class-a-hardening: DELETE TestNoSOARRouteMountedBefore205;
// this guard is the single home for "deferred != orphan."
//
//  1. EVERY Handlers method is either route-mounted OR on the allow-list — a NEW
//     unmounted handler (a real orphan) fails the build, so the dead-code gate is
//     born able to tell a deliberate seam from an orphan.
//  2. EVERY allow-listed handler still EXISTS as a Handlers method — deleting one of
//     the four fails the build, so a dead-code pass cannot silently remove a
//     deferred-but-real operator op.
//  3. NO allow-listed handler is route-mounted — mounting one of the four
//     prematurely (before its wire contract lands) fails the build.
func TestDeferredHandlers_AllowListIsExact(t *testing.T) {
	all := handlerMethods(t)
	mounted := mountedHandlers(t)

	// Property 1 + the orphan check: every handler is mounted or allow-listed.
	for name := range all {
		if mounted[name] {
			continue
		}
		if !deferredHandlers[name] {
			t.Errorf("Handlers method %q is neither route-mounted nor on the deferredHandlers allow-list: "+
				"it is an unmounted handler with no recorded deferral (a likely orphan). Mount it, or add it to "+
				"the allow-list with a doc reason if its route is deliberately deferred.", name)
		}
	}

	// Property 2: every allow-listed handler still exists.
	for name := range deferredHandlers {
		if !all[name] {
			t.Errorf("deferredHandlers lists %q but no such Handlers method exists: a deferred-but-real operator "+
				"op was deleted, or the allow-list is stale. Restore the handler, or remove it from the allow-list "+
				"if it was intentionally dropped.", name)
		}
	}

	// Property 3: no allow-listed handler is route-mounted.
	for name := range deferredHandlers {
		if mounted[name] {
			t.Errorf("deferredHandlers lists %q as not-yet-mounted, but a route invokes it: its wire route was "+
				"mounted before its contract landed. Remove it from the allow-list when you mount it deliberately.", name)
		}
	}
}

// handlerMethods parses EVERY non-test .go file in the package directory and
// returns the set of exported method names on the *Handlers receiver (the full
// in-process operator surface). It scans the whole package, not a single named
// file, so an exported *Handlers method added in any file is in scope — a handler
// defined outside operator.go cannot be a silently-missed orphan.
func handlerMethods(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, file := range parsePackageFiles(t) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			if receiverTypeName(fn.Recv.List[0].Type) != "Handlers" {
				continue
			}
			// Exported methods only — the operator operations. Unexported helpers
			// (resolveCaller) are not wire-mountable operations.
			if fn.Name.IsExported() {
				out[fn.Name.Name] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no *Handlers methods from the package; the AST walk is broken")
	}
	return out
}

// mountedHandlers parses EVERY non-test .go file in the package and returns the set
// of Handlers method names invoked from a route registration. It matches a call
// whose receiver resolves to the handlers — either the local alias `h` (h := l.handlers)
// OR the field access `l.handlers` directly — so a deferred handler mounted via the
// equivalent l.handlers.<Method>( expression cannot evade the not-mounted check.
func mountedHandlers(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, file := range parsePackageFiles(t) {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if receiverIsHandlers(sel.X) {
				out[sel.Sel.Name] = true
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatal("parsed no mounted handler calls from the package; the AST walk is broken")
	}
	return out
}

// parsePackageFiles parses every non-test .go file in this package's directory, so
// the guard reasons over the WHOLE package surface rather than a single named file
// (a handler or a route in any file is in scope).
func parsePackageFiles(t *testing.T) []*ast.File {
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
	return files
}

// receiverTypeName returns the bare type name of a method receiver (stripping a
// leading pointer), for matching *Handlers.
func receiverTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// receiverIsHandlers reports whether a call's receiver expression resolves to the
// operator handlers — either the local alias `h` (h := l.handlers) or the field
// access `l.handlers` directly. Both forms mount a route on the same surface, so
// the not-mounted fence must recognize both; matching only the bare `h` identifier
// would let an l.handlers.<Method>( mount slip past.
func receiverIsHandlers(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		// The local alias bound at the top of registerRoutes (h := l.handlers).
		return e.Name == "h"
	case *ast.SelectorExpr:
		// A direct field access whose selector is `handlers` (l.handlers). The base
		// is any expression (l, the Listener receiver), so this catches the field
		// access regardless of the receiver variable name.
		return e.Sel.Name == "handlers"
	}
	return false
}
