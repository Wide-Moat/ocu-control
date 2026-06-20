// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// auditPkgPath is the leaf audit port whose dependency closure must stay
// stdlib-only: a layer that holds only the AuditSink contract must never drag the
// OCSF serializer, the chain sink, or any heavier internal seam into its import
// graph.
const auditPkgPath = "github.com/Wide-Moat/ocu-control/internal/audit"

// ocsfPkgPath is the sub-package that depends on the leaf one-directionally; the leaf
// must NEVER import it back, or the leaf property collapses.
const ocsfPkgPath = "github.com/Wide-Moat/ocu-control/internal/audit/ocsf"

// modRoot walks up from this file to the directory holding go.mod.
func modRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		matches, _ := filepath.Glob(filepath.Join(dir, "go.mod"))
		if len(matches) == 1 {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// TestAuditIsLeafStdlibOnly asserts the audit port's transitive closure names no
// internal package and no third-party module — it is a stdlib-only leaf. In
// particular it must NOT transitively import its own ocsf sub-package, so the
// one-directional dependency (ocsf → audit, never the reverse) is a build fact, not
// a convention. This keeps the fail-closed Emit seam holdable by every layer above
// without import bloat.
func TestAuditIsLeafStdlibOnly(t *testing.T) {
	t.Parallel()
	root := modRoot(t)
	cmd := exec.Command("go", "list", "-deps", auditPkgPath)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps %s` failed: %v\n%s", auditPkgPath, err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep := strings.TrimSpace(line)
		if dep == auditPkgPath {
			continue // the package itself
		}
		if dep == ocsfPkgPath {
			t.Fatalf("leaf audit transitively imports its ocsf sub-package %q — the dependency must be one-directional (ocsf → audit only)", dep)
		}
		if strings.HasPrefix(dep, "github.com/Wide-Moat/ocu-control/") {
			t.Errorf("leaf audit transitively imports internal package %q; the audit port must stay a stdlib-only leaf", dep)
		}
		// A third-party module path contains a dot before the first slash (a domain);
		// stdlib packages never do. This catches a non-stdlib dependency creeping in.
		if first, _, _ := strings.Cut(dep, "/"); strings.Contains(first, ".") {
			t.Errorf("leaf audit transitively imports third-party module %q; the audit port must stay stdlib-only", dep)
		}
	}
}
