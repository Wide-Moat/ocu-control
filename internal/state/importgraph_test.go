// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state_test

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// statePkgPath is the import path of the ROOT state package — the Store seam, not
// the impl. Its dependency closure must hold no concrete persistence driver. The
// Postgres implementation lives only below the seam, in internal/state/postgres,
// which legitimately imports database/sql; this guard targets the ROOT so a driver
// import cannot creep above the state.Store interface (Invariant I).
const statePkgPath = "github.com/Wide-Moat/ocu-control/internal/state"

// forbiddenStateModules are the concrete-driver module path PREFIXES whose presence
// in the ROOT state closure would mean control logic names a concrete database
// driver (or a container SDK). Unlike cred's exact-match map, this is a PREFIX match:
// database/sql ships database/sql plus database/sql/driver, and the Docker SDK fans
// across many sub-packages — an exact-match set would miss the children. A dep is
// forbidden if it equals or is rooted under any entry here.
var forbiddenStateModules = []string{
	"github.com/jackc/pgx",
	"database/sql",
	"github.com/docker/docker",
	"github.com/moby",
}

// moduleRoot walks up from this test file to the directory holding go.mod so the
// test is independent of the working directory. It is package-local: state_test
// cannot share cred's unexported helper.
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

// forbiddenStateDep reports whether dep is a concrete-driver import: it equals a
// forbidden module path or is rooted under one (prefix + "/"). The trailing-slash
// guard keeps an unrelated sibling from matching by bare prefix.
func forbiddenStateDep(dep string) (string, bool) {
	for _, m := range forbiddenStateModules {
		if dep == m || strings.HasPrefix(dep, m+"/") {
			return m, true
		}
	}
	return "", false
}

// TestStateHoldsNoConcreteDriver asserts the ROOT state package can never grow a
// concrete-persistence dependency above its seam: neither its own source (an AST scan
// for a forbidden direct import) nor its transitive import closure (a `go list -deps`
// check) may name database/sql, pgx, the Docker SDK, or the moby toolkit. The Postgres
// impl lives legitimately below the seam in internal/state/postgres; this guard pins
// that the state.Store interface, not a concrete driver, is what control logic reaches
// (Invariant I).
func TestStateHoldsNoConcreteDriver(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	stateDir := filepath.Join(root, "internal", "state")

	// (a) Source scan: no non-test ROOT state file may directly import a concrete
	// driver. This is the source half.
	scanSourceForConcreteDriver(t, stateDir)

	// (b) Transitive closure: the ROOT state package's full dependency set must
	// exclude every forbidden module, catching an indirect reach the source scan
	// would miss. This is the transitive half.
	assertDepsExcludeConcreteDriver(t, root)
}

// scanSourceForConcreteDriver parses every non-test source file directly in the ROOT
// state directory and fails on a direct import of a forbidden concrete-driver module.
func scanSourceForConcreteDriver(t *testing.T, dir string) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read state dir %s: %v", dir, err)
	}
	parsed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		parsed++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if m, bad := forbiddenStateDep(p); bad {
				t.Errorf("state source %s directly imports forbidden concrete-driver package %q (under %q); "+
					"control logic must depend on the state.Store seam, not a concrete driver", e.Name(), p, m)
			}
		}
	}
	// Anti-vacuity: the source half must have scanned at least one file, or it would
	// pass green having checked nothing (e.g. if the package layout changed).
	if parsed == 0 {
		t.Fatalf("scanned zero non-test source files in %s; the source-import guard is vacuous", dir)
	}
}

// assertDepsExcludeConcreteDriver shells out to `go list -deps` for the ROOT state
// package and fails if its transitive closure includes any forbidden concrete-driver
// module.
func assertDepsExcludeConcreteDriver(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", statePkgPath)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps %s` failed: %v\n%s", statePkgPath, err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep := strings.TrimSpace(line)
		if m, bad := forbiddenStateDep(dep); bad {
			t.Errorf("state package transitively imports %q (under forbidden module %q); the concrete persistence "+
				"driver must stay below the state.Store seam", dep, m)
		}
	}
}
