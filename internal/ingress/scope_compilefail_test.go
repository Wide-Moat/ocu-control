// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress_test

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fixtureRelPath is the //go:build ignore negative fixture this test compiles. It
// is resolved relative to THIS test file's directory (via runtime.Caller) so the
// test is independent of the working directory `go test` runs in.
const fixtureRelPath = "testdata/scope_compilefail/forge.go"

// forbiddenConstructs are the forgeries forge.go attempts; each MUST surface a
// compile diagnostic. A substring per forgery is asserted against the `go build`
// output, so the test fails loudly if any single forgery ever starts compiling
// (the seal regressing from a compile fact to a runtime hope) rather than only
// checking the overall exit code.
var forbiddenConstructs = []struct {
	what string // human label for the failure message
	want string // a stable substring of the expected compiler diagnostic
}{
	{"literal-forge of OperatorScope (unexported field w)", "unexported field w"},
	{"naming the unexported operatorWitness type", "operatorWitness not exported"},
	{"literal-forge of OperatorSeam (unexported field mint)", "unexported field mint"},
	{"passing a ServiceScope where an OperatorScope is required", "as ingress.OperatorScope value"},
	{"converting a ServiceScope to an OperatorScope", "cannot convert"},
	// The mcpkey Engine methods also take ingress.OperatorScope; a gateway-shaped
	// caller that holds no seam cannot mint one and therefore cannot call Create or
	// Revoke. The forge below attempts to call the engine with a ServiceScope (the
	// gateway's capability) and must fail with the same type mismatch.
	{"passing ServiceScope to mcpkey.Engine.Create (gateway cannot reach mcp-key create)", "as ingress.OperatorScope value"},
}

// TestScopeCompileFailFixtureDoesNotCompile is the load-bearing compile seal: it
// runs `go build` on the negative fixture and asserts (a) the build FAILS (non-zero
// exit) and (b) the diagnostics name every forbidden construct. The fixture carries
// a //go:build ignore tag so it is never part of the package build, vet, lint, or
// `go test`; only this explicit `go build` on the exact file path ever compiles it.
//
// If this test ever passes the build (exit zero), a foreign package can forge an
// OperatorScope or call an operator-only method from a gateway-shaped caller, and
// the two-listener scope separation (NFR-SEC-52) has degraded to a runtime check.
func TestScopeCompileFailFixtureDoesNotCompile(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the fixture relative to the test")
	}
	fixture := filepath.Join(filepath.Dir(thisFile), fixtureRelPath)

	// `go build <file>.go` type-checks and compiles the single file as
	// command-line-arguments; the //go:build ignore tag does not suppress an
	// explicitly named file, so the forgeries are compiled and rejected here.
	cmd := exec.Command("go", "build", fixture)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err == nil {
		t.Fatalf("FORGERY COMPILED: `go build %s` succeeded; the capability seal is broken.\noutput:\n%s", fixture, output)
	}

	for _, fc := range forbiddenConstructs {
		if !strings.Contains(output, fc.want) {
			t.Errorf("expected a compile diagnostic for %s (substring %q), not found in build output:\n%s",
				fc.what, fc.want, output)
		}
	}
}
