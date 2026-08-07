// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ADR-0040's first binding property: the registered method-and-path set equals
// the frozen document's operation set, in both directions.
//
// TestRegisterRoutesMountsExactlyTheExpectedSet next door already fences the
// mounted set — but against expectedMountedRoutes, a list maintained by hand.
// That catches a route added without updating the list; it cannot catch the list
// and the code agreeing with each other while both diverge from the contract.
// Binding to the document closes that: a route the contract does not declare is
// a surface no audit of the document reveals, and an operation the contract
// declares with no route is a documented endpoint that answers 404.

// contractOperations returns the document's operations as "METHOD /path"
// patterns, matching the shape http.ServeMux registers.
func contractOperations(t *testing.T) map[string]bool {
	t.Helper()
	doc := operatorContract(t)
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatal("the contract declares no paths; an empty set would satisfy every " +
			"comparison below")
	}

	out := map[string]bool{}
	for path, rawOps := range paths {
		ops, ok := rawOps.(map[string]any)
		if !ok {
			continue
		}
		for method := range ops {
			m := strings.ToUpper(method)
			// Only HTTP verbs are operations; a path-level `parameters` or
			// `summary` key is not one, and counting it would invent an
			// operation the mux could never match.
			switch m {
			case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE":
			default:
				continue
			}
			out[fmt.Sprintf("%s %s", m, path)] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("no operations parsed from the contract's paths; the parser no longer " +
			"matches the document's shape, so an empty result would compare against nothing")
	}
	return out
}

// TestMountedRoutesMatchTheContractOperations binds the two sets.
func TestMountedRoutesMatchTheContractOperations(t *testing.T) {
	want := contractOperations(t)
	got := registerRoutesPatterns(t)

	for pattern := range got {
		if !want[pattern] {
			t.Errorf("the mux mounts %q, which the frozen contract does not declare — "+
				"the served surface is wider than the audited one", pattern)
		}
	}
	for pattern := range want {
		if !got[pattern] {
			t.Errorf("the contract declares %q but no route mounts it — a caller "+
				"following the document reaches a 404", pattern)
		}
	}

	if t.Failed() {
		t.Logf("contract operations: %v", sortedKeys(want))
		t.Logf("mounted routes:     %v", sortedKeys(got))
	}
}

// TestExpectedMountedRoutesTracksTheContract keeps the hand-maintained list from
// drifting into a second, quieter source of truth. Without it the list could be
// edited to match a diverged mux and both would agree while the contract said
// something else — the shape of drift ADR-0040 exists to remove.
func TestExpectedMountedRoutesTracksTheContract(t *testing.T) {
	want := contractOperations(t)
	for pattern := range expectedMountedRoutes {
		if !want[pattern] {
			t.Errorf("expectedMountedRoutes lists %q, which the contract does not "+
				"declare; the list is tracking the code rather than the document", pattern)
		}
	}
	for pattern := range want {
		if !expectedMountedRoutes[pattern] {
			t.Errorf("the contract declares %q but expectedMountedRoutes omits it", pattern)
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
