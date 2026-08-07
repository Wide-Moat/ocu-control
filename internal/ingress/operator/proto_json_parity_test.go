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

// frozenProtoPath locates the vendored contract both parity checks read.
func frozenProtoPath() string {
	return filepath.Join("..", "..", "..", "contracts", "proto", "ocu", "control", "session", "v1", "session_setup.proto")
}

// protoFieldsOf extracts the field names of one proto message, in declaration
// order. It parses the contract rather than importing generated code, because
// there is none — that absence is the reason this test exists.
func protoFieldsOf(t *testing.T, message string) []string {
	t.Helper()
	path := frozenProtoPath()
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

// parityCase pairs one frozen proto message with the hand-written wire body
// that carries it.
type parityCase struct {
	message string
	body    any
	// omitted are proto fields the wire body deliberately does not carry.
	// Each needs a reason: an unexplained omission is a field the transport
	// silently drops.
	omitted map[string]string
}

// parityCases is the covered set. It is package-level so the coverage test
// below can read it: a hand-maintained list that nothing checks for
// completeness binds only the messages someone remembered to add, while
// reading as though it binds the wire.
var parityCases = []parityCase{
	{message: "EgressPolicy", body: egressPolicyBody{}},
	{message: "MountIntent", body: mountIntentBody{}},
}

// protoMessagesNotSharedWithThisSurface names frozen messages whose wire shape
// this transport does NOT share, each with the contract that governs it here.
//
// Two contracts meet on this transport. The proto freezes the session-setup
// gRPC surface; operator-rest.openapi.yaml freezes the operator REST surface.
// Most bodies belong to one or the other, and contract_binding_test.go binds
// the REST side. Only the shapes the two surfaces deliberately SHARE —
// mount_intent and egress_policy, embedded verbatim in both so one JSON body
// serves both — are bound here, against the proto.
//
// An entry is a claim about which contract governs, not a licence to skip
// checking: every message named here must be bound by the named test.
var protoMessagesNotSharedWithThisSurface = map[string]string{
	"CreateRequest":   "operator REST body; bound to the OpenAPI CreateRequest by TestCreateBodyServesOnlyDeclaredFields",
	"CreateResponse":  "operator REST reply; bound to the OpenAPI SessionHandle by TestSessionResponseMatchesSessionHandle",
	"RouteResponse":   "same sessionResponse as CreateResponse, bound by TestSessionResponseMatchesSessionHandle",
	"BoundedReason":   "refusal envelope; bound to the OpenAPI BoundedReason by TestDenyBodiesAreTheContractEnvelope",
	"ResourceCaps":    "stamped on the runtime from deployment config; not decoded off an operator body",
	"RouteRequest":    "the operator REST route carries the session key in the path, not a body",
	"DestroyRequest":  "operator REST body keyed by session_hint; the gRPC surface keys by host-derived session_id",
	"DestroyResponse": "empty message; the REST verb answers with no body",
}

// TestEveryFrozenMessageIsBoundOrExcused is the completeness check the parity
// list lacked. parityCases is hand-maintained, and nothing checked its EXTENT —
// only its contents. A message added to the contract, or a shared shape that
// grows a second consumer, would simply never appear here, and the gate would
// keep reporting the same green while covering less of the surface.
//
// Every excuse names the test that binds the message instead, so "not bound
// here" can never quietly mean "not bound anywhere".
func TestEveryFrozenMessageIsBoundOrExcused(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range parityCases {
		covered[c.message] = true
	}

	all := protoMessageNames(t)
	if len(all) < 5 {
		t.Fatalf("parsed only %d messages from the contract; the parser no longer "+
			"matches its syntax and this check would pass vacuously", len(all))
	}

	for _, m := range all {
		if covered[m] {
			continue
		}
		if _, excused := protoMessagesNotSharedWithThisSurface[m]; excused {
			continue
		}
		t.Errorf("frozen message %q is neither in parityCases nor excused in "+
			"protoMessagesNotSharedWithThisSurface; if the transport carries it, its wire body "+
			"is unbound to the contract, and if it does not, say so with a reason", m)
	}

	// The other direction: an excuse naming a message the contract no longer
	// defines is a note the next reader would trust wrongly.
	defined := map[string]bool{}
	for _, m := range all {
		defined[m] = true
	}
	for m := range protoMessagesNotSharedWithThisSurface {
		if !defined[m] {
			t.Errorf("protoMessagesNotSharedWithThisSurface excuses %q, which the frozen contract "+
				"does not define", m)
		}
	}
	for _, c := range parityCases {
		if !defined[c.message] {
			t.Errorf("parityCases binds %q, which the frozen contract does not define", c.message)
		}
	}
}

// TestEveryNamedBindingTestExists closes the excuse list's own escape hatch. An
// entry that cites "bound by TestFoo" is trusted by the reader and by the
// coverage check above; if TestFoo is renamed or deleted, the citation becomes
// a note asserting a binding that no longer runs, and nothing would say so.
func TestEveryNamedBindingTestExists(t *testing.T) {
	declared := declaredTestNames(t)
	if len(declared) < 5 {
		t.Fatalf("found %d test functions in the package; the scan is broken and every "+
			"citation below would pass unchecked", len(declared))
	}

	cite := regexp.MustCompile(`\bTest[A-Za-z0-9_]+`)
	checked := 0
	for message, reason := range protoMessagesNotSharedWithThisSurface {
		for _, name := range cite.FindAllString(reason, -1) {
			checked++
			if !declared[name] {
				t.Errorf("the excuse for %q cites %s, which this package does not declare; "+
					"the message is recorded as bound by a test that does not exist",
					message, name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no test citations were found in the excuse list; either the reasons " +
			"stopped naming their binding test, or this check stopped finding them")
	}
}

// declaredTestNames collects the Test* functions this package declares, read
// from the source rather than from a hand-kept list.
func declaredTestNames(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	out := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range decl.FindAllSubmatch(raw, -1) {
			out[string(m[1])] = true
		}
	}
	return out
}

// protoMessageNames lists every message the frozen contract declares.
func protoMessageNames(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(frozenProtoPath())
	if err != nil {
		t.Fatalf("read frozen proto: %v", err)
	}
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^message ([A-Za-z0-9_]+)`).FindAllSubmatch(raw, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// TestWireBodiesMatchTheFrozenProto is the binding the doc comments only assert.
// A field renamed on either side reds here, naming the delta.
func TestWireBodiesMatchTheFrozenProto(t *testing.T) {
	for _, tc := range parityCases {
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
