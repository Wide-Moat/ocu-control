// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress_test

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

// operatorSeamSymbols are the ingress identifiers that constitute the operator-seam
// MINT PATH: naming any of them is how a package would obtain or forge an
// OperatorScope. The gateway adapter (internal/ingress/gateway) must reference NONE
// of them — it holds only a ServiceScope and must have no syntactic route to the
// operator capability. This list is the anchor the CI import-graph grep (step 12)
// also targets; keeping it in one place keeps the test and the grep in agreement.
var operatorSeamSymbols = []string{
	"OperatorSeam",
	"NewOperatorSeam",
	"OperatorScope",
}

// gatewayPkgPath is the import path of the gateway adapter. The package is built;
// this test scans its real source and its real transitive dependency closure for
// any route to the operator-seam mint path.
const gatewayPkgPath = "github.com/Wide-Moat/ocu-control/internal/ingress/gateway"

// moduleRoot walks up from this test file to the directory holding go.mod, so the
// test is independent of the working directory go test runs in.
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

// TestGatewayCannotReachOperatorSeam asserts the operator-seam mint path is
// unreachable from the gateway adapter: neither its source (an AST scan for the
// forbidden identifiers) nor its transitive import set (a `go list -deps` check)
// may name the operator-seam symbols or the operator/kill-switch packages. This is
// the import-graph half of the capability seal (the compile-fail fixture is the
// type half); together they make the gateway↛operator separation a mechanical fact.
//
// The test also verifies the structural anchor — that the forbidden symbols are real
// exported names of THIS package, so the grep/scan target is well-defined — before
// scanning the built gateway package's source and transitive dependency closure.
func TestGatewayCannotReachOperatorSeam(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	// Structural anchor: the forbidden symbols must exist as exported declarations
	// of the ingress package itself, or the gateway scan below would be checking for
	// ghosts. Parse this package's source and confirm each symbol is declared.
	assertSymbolsDeclaredInIngress(t, root)

	gatewayDir := filepath.Join(root, "internal", "ingress", "gateway")

	// (a) Source scan: no gateway source file may reference an operator-seam symbol.
	scanGatewaySourceForForbiddenSymbols(t, gatewayDir)

	// (b) Transitive import scan: the gateway package's full dependency closure must
	// not include the operator or kill-switch packages (where the seam is held and
	// the operator-only methods live).
	assertGatewayDepsExcludeOperatorPath(t, root)
}

// assertSymbolsDeclaredInIngress parses the ingress package source (this directory)
// and fails if any forbidden symbol is NOT a top-level declaration, so the scan
// target list cannot silently rot if a symbol is renamed.
func assertSymbolsDeclaredInIngress(t *testing.T, root string) {
	t.Helper()
	ingressDir := filepath.Join(root, "internal", "ingress")
	declared := topLevelDecls(t, ingressDir)
	for _, sym := range operatorSeamSymbols {
		if !declared[sym] {
			t.Errorf("operator-seam symbol %q is not a top-level declaration of package ingress; "+
				"the import-graph scan target is stale (rename it in operatorSeamSymbols too)", sym)
		}
	}
}

// topLevelDecls returns the set of top-level type/func names declared across the
// non-test Go files directly in dir (one package, no recursion).
func topLevelDecls(t *testing.T, dir string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	names := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil { // top-level func, not a method
					names[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if ts, isType := spec.(*ast.TypeSpec); isType {
						names[ts.Name.Name] = true
					}
				}
			}
		}
	}
	return names
}

// scanGatewaySourceForForbiddenSymbols parses every non-test gateway source file and
// fails on any identifier that names an operator-seam symbol. A selector like
// ingress.OperatorScope appears as a SelectorExpr whose Sel is the symbol; a bare
// identifier (in the unlikely event of a dot-import) appears as an Ident. Both are
// caught by inspecting every Ident node's name.
func scanGatewaySourceForForbiddenSymbols(t *testing.T, gatewayDir string) {
	t.Helper()
	forbidden := map[string]bool{}
	for _, s := range operatorSeamSymbols {
		forbidden[s] = true
	}
	// Mint is the method name on OperatorSeam; flag it too so an aliased seam value
	// cannot mint without tripping the scan.
	forbidden["Mint"] = true

	fset := token.NewFileSet()
	entries, err := os.ReadDir(gatewayDir)
	if err != nil {
		t.Fatalf("read gateway dir %s: %v", gatewayDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(gatewayDir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse gateway file %s: %v", e.Name(), perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, isIdent := n.(*ast.Ident); isIdent && forbidden[id.Name] {
				t.Errorf("gateway source %s references forbidden operator-seam symbol %q at %s; "+
					"the gateway adapter must not reach the operator-seam mint path",
					e.Name(), id.Name, fset.Position(id.Pos()))
			}
			return true
		})
	}
}

// assertGatewayDepsExcludeOperatorPath shells out to `go list -deps` for the gateway
// package and fails if its transitive dependency closure contains the operator or
// kill-switch packages, where the seam is custodied and the operator-only surface
// lives. This catches an indirect reach the source scan alone would miss.
func assertGatewayDepsExcludeOperatorPath(t *testing.T, root string) {
	t.Helper()
	forbiddenPkgs := []string{
		"github.com/Wide-Moat/ocu-control/internal/ingress/operator",
		"github.com/Wide-Moat/ocu-control/internal/killswitch",
	}
	cmd := exec.Command("go", "list", "-deps", gatewayPkgPath)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps %s` failed: %v\n%s", gatewayPkgPath, err, out)
	}
	deps := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		deps[strings.TrimSpace(line)] = true
	}
	for _, fp := range forbiddenPkgs {
		if deps[fp] {
			t.Errorf("gateway package %s transitively imports %s; the gateway must not reach the operator-seam path",
				gatewayPkgPath, fp)
		}
	}
}
