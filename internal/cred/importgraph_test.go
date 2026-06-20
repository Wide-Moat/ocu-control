// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// credPkgPath is the import path of the custody core whose dependency closure
// must hold no listener.
const credPkgPath = "github.com/Wide-Moat/ocu-control/internal/cred"

// forbiddenClosureImports are the standard-library packages whose presence in
// the transitive closure would mean the custody core can stand up an HTTP
// listener or server. net/http is the home of http.Server / http.ListenAndServe;
// keeping it out of the closure makes "issuance is an in-process method call,
// never an RPC" a mechanical fact (requirement 1). Bare net is intentionally NOT
// here: the golang-jwt parser pulls net/url (JWT x5u/jku header URLs) which
// transitively names net, a benign import that grants no listener capability —
// the listener home is net/http, and that stays out.
var forbiddenClosureImports = map[string]bool{
	"net/http": true,
}

// forbiddenSourceImports are packages no cred SOURCE file may import directly. A
// custody core has no business dialing or listening; the JWT library may reach
// net/url transitively, but cred's own code must not name net or net/http.
var forbiddenSourceImports = map[string]bool{
	"net":      true,
	"net/http": true,
}

// forbiddenSymbols are listener/server identifiers no cred source file may name.
// They are the AST half of the no-listener seal; the import-closure check below
// is the transitive half.
var forbiddenSymbols = map[string]bool{
	"Listener": true,
	"Listen":   true,
	"Server":   true,
}

// moduleRoot walks up from this test file to the directory holding go.mod so the
// test is independent of the working directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the module root")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// TestCredHoldsNoListener asserts the custody core can never grow a network
// issuance endpoint: neither its own source (an AST scan for listener/server
// identifiers and forbidden imports) nor its transitive import closure (a
// `go list -deps` check) may name net/net/http or a listener symbol. Together
// they make "issuance is an in-process method call, never an RPC" a structural
// guarantee the build enforces.
func TestCredHoldsNoListener(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	credDir := filepath.Join(root, "internal", "cred")

	// (a) Source scan: no non-test cred file may import a forbidden package or
	// name a listener/server symbol.
	scanSourceForListener(t, credDir)

	// (b) Transitive closure: the cred package's full dependency set must exclude
	// net and net/http, catching an indirect reach the source scan would miss.
	assertDepsExcludeNet(t, root)
}

// scanSourceForListener parses every non-test cred source file and fails on a
// forbidden import or a listener/server identifier.
func scanSourceForListener(t *testing.T, dir string) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cred dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbiddenSourceImports[p] {
				t.Errorf("cred source %s imports forbidden package %q; the custody core must hold no listener", e.Name(), p)
			}
		}
		// A full parse is needed to scan identifiers (selectors like net.Listen).
		ff, ferr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if ferr != nil {
			t.Fatalf("parse %s: %v", e.Name(), ferr)
		}
		ast.Inspect(ff, func(n ast.Node) bool {
			if id, isIdent := n.(*ast.Ident); isIdent && forbiddenSymbols[id.Name] {
				t.Errorf("cred source %s names forbidden listener symbol %q at %s",
					e.Name(), id.Name, fset.Position(id.Pos()))
			}
			return true
		})
	}
}

// assertDepsExcludeNet shells out to `go list -deps` and fails if the cred
// package's transitive closure includes net or net/http.
func assertDepsExcludeNet(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", credPkgPath)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps %s` failed: %v\n%s", credPkgPath, err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep := strings.TrimSpace(line)
		if forbiddenClosureImports[dep] {
			t.Errorf("cred package transitively imports %q; the custody core must hold no listener", dep)
		}
	}
}
