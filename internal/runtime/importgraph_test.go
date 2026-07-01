// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package runtime_test

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

// runtimePkgPath is the import path of the ROOT runtime package — the seam, not
// the impl. Its dependency closure must hold no concrete substrate SDK. The Docker
// SDK lives only below the seam, in internal/runtime/docker, which legitimately
// imports it; this guard targets the ROOT so a concrete-SDK import cannot creep
// above the RuntimeProvider interface (Invariant I).
const runtimePkgPath = "github.com/Wide-Moat/ocu-control/internal/runtime"

// forbiddenRuntimeModules are the concrete-substrate module path PREFIXES whose
// presence in the ROOT runtime closure would mean control logic names a concrete
// container SDK or database driver. Unlike cred's exact-match map, this is a
// PREFIX match: the Docker SDK is fanned across many sub-packages
// (github.com/docker/docker/api/types/mount, .../blkiodev, ...) and database/sql
// ships database/sql plus database/sql/driver — an exact-match set would miss the
// children. A dep is forbidden if it equals or is rooted under any entry here.
var forbiddenRuntimeModules = []string{
	"github.com/docker/docker",
	"github.com/moby",
	"github.com/jackc/pgx",
	"database/sql",
}

// moduleRoot walks up from this test file to the directory holding go.mod so the
// test is independent of the working directory. It is package-local: runtime_test
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

// forbiddenRuntimeDep reports whether dep is a concrete-substrate import: it equals
// a forbidden module path or is rooted under one (prefix + "/"). The trailing-slash
// guard keeps an unrelated sibling like "database/sql-helper" (hypothetical) from
// matching "database/sql" by bare prefix.
func forbiddenRuntimeDep(dep string) (string, bool) {
	for _, m := range forbiddenRuntimeModules {
		if dep == m || strings.HasPrefix(dep, m+"/") {
			return m, true
		}
	}
	return "", false
}

// TestRuntimeHoldsNoConcreteSDK asserts the ROOT runtime package can never grow a
// concrete-substrate dependency above its seam: neither its own source (an AST scan
// for a forbidden direct import) nor its transitive import closure (a `go list -deps`
// check) may name the Docker SDK, the moby toolkit, pgx, or database/sql. The Docker
// SDK lives legitimately below the seam in internal/runtime/docker; this guard pins
// that the RuntimeProvider interface, not a concrete SDK, is what control logic
// reaches (Invariant I).
func TestRuntimeHoldsNoConcreteSDK(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	runtimeDir := filepath.Join(root, "internal", "runtime")

	// (a) Source scan: no non-test ROOT runtime file may directly import a concrete
	// substrate SDK. This is the source half.
	scanSourceForConcreteSDK(t, runtimeDir, "runtime")

	// (b) Transitive closure: the ROOT runtime package's full dependency set must
	// exclude every forbidden module, catching an indirect reach the source scan
	// would miss. This is the transitive half.
	assertDepsExcludeConcreteSDK(t, root, runtimePkgPath, "runtime")
}

// scanSourceForConcreteSDK parses every non-test source file directly in dir and
// fails on a direct import of a forbidden concrete-substrate module. label names the
// package in failures.
func scanSourceForConcreteSDK(t *testing.T, dir, label string) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s dir %s: %v", label, dir, err)
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
			if m, bad := forbiddenRuntimeDep(p); bad {
				t.Errorf("%s source %s directly imports forbidden concrete-substrate package %q (under %q); "+
					"control logic must depend on the seam interface, not a concrete SDK", label, e.Name(), p, m)
			}
		}
	}
	// Anti-vacuity: the source half must have scanned at least one file, or it would
	// pass green having checked nothing (e.g. if the package layout changed).
	if parsed == 0 {
		t.Fatalf("scanned zero non-test source files in %s; the source-import guard is vacuous", dir)
	}
}

// assertDepsExcludeConcreteSDK shells out to `go list -deps` for pkg and fails if its
// transitive closure includes any forbidden concrete-substrate module. label names the
// package in failures.
func assertDepsExcludeConcreteSDK(t *testing.T, root, pkg, label string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps %s` failed: %v\n%s", pkg, err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep := strings.TrimSpace(line)
		if m, bad := forbiddenRuntimeDep(dep); bad {
			t.Errorf("%s package transitively imports %q (under forbidden module %q); the concrete substrate SDK "+
				"must stay below the RuntimeProvider seam", label, dep, m)
		}
	}
}
