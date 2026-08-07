// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The control plane ships no generated .pb.go: the wire bodies are hand-written
// Go structs whose doc comments CLAIM their JSON tags follow the frozen
// session_setup.proto. A claim in a comment binds nothing — rename a proto field
// or a struct tag and every existing transport test still passes, because those
// tests drive the wire against Go structs and never read the contract.
//
// These tests read the frozen proto and require the two to agree, so the wire
// surface is checked against the contract rather than against itself.

// protoFieldsOf extracts the field names of one proto message, in declaration
// order. It parses the contract rather than importing generated code, because
// there is none — that absence is the reason this test exists.
func protoFieldsOf(t *testing.T, message string) []string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "contracts", "proto", "ocu", "control", "session", "v1", "session_setup.proto")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen proto: %v", err)
	}

	block := regexp.MustCompile(`(?s)\nmessage ` + regexp.QuoteMeta(message) + ` \{(.*?)\n\}`)
	m := block.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("message %q not found in %s — the contract moved or was renamed, and "+
			"this parity test is now measuring nothing", message, path)
	}

	// A scalar/repeated field line: optional label, type, name, = tag;
	field := regexp.MustCompile(`(?m)^\s*(?:repeated\s+)?[A-Za-z0-9_.]+\s+([a-z][a-z0-9_]*)\s*=\s*\d+\s*;`)
	var out []string
	for _, f := range field.FindAllSubmatch(m[1], -1) {
		out = append(out, string(f[1]))
	}
	if len(out) == 0 {
		t.Fatalf("no fields parsed from message %q; the parser no longer matches the "+
			"contract's syntax, so an empty result would pass every comparison", message)
	}
	return out
}

// jsonTagsOf returns the json tag names of a struct, in declaration order.
func jsonTagsOf(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			t.Fatalf("field %s carries no json tag; the wire name would fall back to the "+
				"Go name and silently diverge from the contract", rt.Field(i).Name)
		}
		out = append(out, name)
	}
	return out
}

// TestWireBodiesMatchTheFrozenProto is the binding the doc comments only assert.
// A field renamed on either side reds here, naming the delta.
func TestWireBodiesMatchTheFrozenProto(t *testing.T) {
	cases := []struct {
		message string
		body    any
		// omitted are proto fields the wire body deliberately does not carry.
		// Each needs a reason: an unexplained omission is a field the transport
		// silently drops.
		omitted map[string]string
	}{
		{message: "EgressPolicy", body: egressPolicyBody{}},
		{message: "MountIntent", body: mountIntentBody{}},
	}

	for _, tc := range cases {
		t.Run(tc.message, func(t *testing.T) {
			want := protoFieldsOf(t, tc.message)
			got := jsonTagsOf(t, tc.body)

			wantSet := map[string]bool{}
			for _, f := range want {
				wantSet[f] = true
			}
			gotSet := map[string]bool{}
			for _, f := range got {
				gotSet[f] = true
			}

			for _, f := range want {
				if !gotSet[f] {
					if reason, ok := tc.omitted[f]; ok {
						t.Logf("proto field %q deliberately absent from the wire body: %s", f, reason)
						continue
					}
					t.Errorf("proto field %q has no json tag on %T — a client sending the "+
						"contract's field name would have it silently dropped by the decoder",
						f, tc.body)
				}
			}
			for _, f := range got {
				if !wantSet[f] {
					t.Errorf("json tag %q on %T names no field in the frozen %s message — "+
						"the wire carries a field the contract does not define",
						f, tc.body, tc.message)
				}
			}
		})
	}
}

// TestWireBodyFieldOrderMatchesTheProto is separate from the set comparison
// above, and deliberately weaker in what it claims: JSON is order-insensitive on
// the wire, so a reordering breaks no client. It is pinned because the struct is
// the human-readable mirror of the contract — a reader diffing the two by eye is
// how a missing field gets noticed, and that reading only works while the order
// holds.
func TestWireBodyFieldOrderMatchesTheProto(t *testing.T) {
	for _, tc := range []struct {
		message string
		body    any
	}{
		{message: "EgressPolicy", body: egressPolicyBody{}},
		{message: "MountIntent", body: mountIntentBody{}},
	} {
		t.Run(tc.message, func(t *testing.T) {
			want := protoFieldsOf(t, tc.message)
			got := jsonTagsOf(t, tc.body)
			if len(want) != len(got) {
				t.Skipf("field counts differ (%d proto vs %d wire); the set comparison "+
					"reports that, and an order check on differing sets is noise", len(want), len(got))
			}
			if !reflect.DeepEqual(want, got) {
				sw, sg := append([]string(nil), want...), append([]string(nil), got...)
				sort.Strings(sw)
				sort.Strings(sg)
				if reflect.DeepEqual(sw, sg) {
					t.Errorf("%T declares the contract's fields in a different order:\n proto %v\n  wire %v",
						tc.body, want, got)
				}
			}
		})
	}
}
