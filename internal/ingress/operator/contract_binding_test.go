// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/state"
	"gopkg.in/yaml.v3"
)

// ADR-0040 admits a hand-written surface only under a binding driven by the
// frozen document itself. These tests parse operator-rest.openapi.yaml — never
// constants transcribed out of it — so a divergence between what the contract
// declares and what the handlers emit is a failing test rather than a comment
// nobody rechecks.
//
// The field-name parity test next door binds names for two proto messages. That
// is the property transcription tends to preserve: the response shape, the state
// enum and the deny envelope all drifted while it stayed green.

// operatorContract loads the frozen document as a generic tree. It is
// deliberately untyped: a struct would silently drop whatever it does not model,
// and a test that cannot see a field cannot bind it.
func operatorContract(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "..", "contracts", "openapi", "operator-rest.openapi.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read frozen operator contract: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse frozen operator contract: %v", err)
	}
	if len(doc) == 0 {
		t.Fatal("the contract parsed to an empty document; every comparison below " +
			"would pass against nothing")
	}
	return doc
}

// schemaOf resolves components.schemas.<name> from the document.
func schemaOf(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	s, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("schema %q not found in the frozen contract — it was renamed or "+
			"removed, and this test is now measuring nothing", name)
	}
	return s
}

func propertyNames(t *testing.T, schema map[string]any) []string {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok || len(props) == 0 {
		t.Fatal("schema declares no properties; an empty set would satisfy every comparison")
	}
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jsonNamesOf returns the json tag names a Go struct marshals.
func jsonNamesOf(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TestSessionResponseMatchesSessionHandle binds the create/route response to the
// schema the contract declares for it. A client generated from the contract
// reads session_key; a response carrying key leaves it holding nothing.
func TestSessionResponseMatchesSessionHandle(t *testing.T) {
	doc := operatorContract(t)
	schema := schemaOf(t, doc, "SessionHandle")

	want := propertyNames(t, schema)
	got := jsonNamesOf(t, sessionResponse{})
	if !reflect.DeepEqual(want, got) {
		t.Errorf("sessionResponse marshals %v; the contract's SessionHandle declares %v",
			got, want)
	}

	// Every property the contract marks required must be present, since a
	// conforming client may rely on it unconditionally.
	if req, ok := schema["required"].([]any); ok {
		have := map[string]bool{}
		for _, n := range got {
			have[n] = true
		}
		for _, r := range req {
			name, _ := r.(string)
			if !have[name] {
				t.Errorf("SessionHandle requires %q but sessionResponse never emits it", name)
			}
		}
	}
}

// TestSessionStateIsTheContractEnum binds the state representation. A numeric
// state is not merely a different spelling: a client validating against the
// contract's string enum rejects the response outright.
func TestSessionStateIsTheContractEnum(t *testing.T) {
	doc := operatorContract(t)
	schema := schemaOf(t, doc, "SessionHandle")
	props, _ := schema["properties"].(map[string]any)
	state, ok := props["state"].(map[string]any)
	if !ok {
		t.Fatal("SessionHandle declares no state property")
	}

	if got, want := state["type"], "string"; got != want {
		t.Fatalf("the contract's state type is %v, not %v — this test was written "+
			"against the string enum", got, want)
	}
	rawEnum, ok := state["enum"].([]any)
	if !ok || len(rawEnum) == 0 {
		t.Fatal("the contract's state carries no enum; there is nothing to bind")
	}
	allowed := map[string]bool{}
	for _, e := range rawEnum {
		s, _ := e.(string)
		allowed[s] = true
	}

	// Marshal the wire struct and require the emitted state to be a member.
	rt := reflect.TypeOf(sessionResponse{})
	f, ok := rt.FieldByName("State")
	if !ok {
		t.Fatal("sessionResponse has no State field")
	}
	if f.Type.Kind() != reflect.String {
		t.Fatalf("sessionResponse.State is %s; the contract declares a string enum %v, "+
			"so a conforming client rejects this response", f.Type.Kind(), rawEnum)
	}

	// Each state the store can reach must map onto a declared enum member, so a
	// state added later cannot serialize to something the contract does not list.
	for _, st := range allSessionStates() {
		wire := sessionStateWire(st)
		if !allowed[wire] {
			t.Errorf("store state %v serializes to %q, which the contract's enum %v "+
				"does not declare", st, wire, rawEnum)
		}
	}
}

// TestDenyBodiesAreTheContractEnvelope binds the refusal shape. The contract
// declares one Denied response carrying BoundedReason as JSON; a text/plain
// status line is unparseable to a conforming client, which is what NFR-SEC-51
// asks the envelope to prevent.
func TestDenyBodiesAreTheContractEnvelope(t *testing.T) {
	doc := operatorContract(t)
	comps, _ := doc["components"].(map[string]any)
	responses, _ := comps["responses"].(map[string]any)
	denied, ok := responses["Denied"].(map[string]any)
	if !ok {
		t.Fatal("the contract declares no Denied response; there is nothing to bind")
	}
	content, _ := denied["content"].(map[string]any)
	if _, ok := content["application/json"]; !ok {
		t.Fatalf("the contract's Denied response declares %v, not application/json — "+
			"this test was written against the JSON envelope", keysOf(content))
	}

	// The deny writer must emit that media type and a body that unmarshals.
	rec := recordDeny(t)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("a refusal was written as %q; the contract declares application/json "+
			"(BoundedReason), so a conforming client cannot read the reason", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("a refusal body is not JSON (%v): %q", err, rec.Body.String())
	}

	// The envelope's own constraints are the contract's, so they are read from it
	// rather than restated: a reason_code the pattern rejects is a body a
	// conforming client refuses even though it parsed as JSON.
	br := schemaOf(t, doc, "BoundedReason")
	props, _ := br["properties"].(map[string]any)
	rc, _ := props["reason_code"].(map[string]any)
	pattern, _ := rc["pattern"].(string)
	if pattern == "" {
		t.Fatal("BoundedReason.reason_code declares no pattern; there is nothing to bind")
	}
	re := regexp.MustCompile(pattern)

	if req, ok := br["required"].([]any); ok {
		for _, r := range req {
			name, _ := r.(string)
			if _, present := body[name]; !present {
				t.Errorf("BoundedReason requires %q but the refusal body omits it: %v", name, body)
			}
		}
	}
	got, _ := body["reason_code"].(string)
	if !re.MatchString(got) {
		t.Errorf("reason_code %q does not match the contract pattern %s", got, pattern)
	}

	// Every status the deny writer can produce must yield a conforming code, so a
	// status added later cannot emit one the pattern rejects.
	for _, code := range []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable,
		http.StatusInternalServerError,
	} {
		if rcode := reasonCodeFor(code); !re.MatchString(rcode) {
			t.Errorf("status %d yields reason_code %q, which the contract pattern %s rejects",
				code, rcode, pattern)
		}
	}

	// The message bound is the contract's too: an over-long reason is a schema
	// violation, so the writer must cut it rather than emit it.
	msg, _ := props["message"].(map[string]any)
	if maxLen, ok := msg["maxLength"].(int); ok {
		long := httptest.NewRecorder()
		writeStatus(long, http.StatusForbidden, strings.Repeat("x", maxLen*2))
		var lb map[string]any
		if err := json.Unmarshal(long.Body.Bytes(), &lb); err != nil {
			t.Fatalf("an over-long refusal body is not JSON: %v", err)
		}
		if s, _ := lb["message"].(string); len(s) > maxLen {
			t.Errorf("a refusal message is %d chars; the contract bounds it at %d", len(s), maxLen)
		}
	}
}

// undeclaredCreateFields are wire fields the contract deliberately withholds,
// each with the reason and the issue that closes it. ADR-0040 admits an
// annotated exception; it does not admit an unexplained one, so an entry here
// must name why the field cannot simply be removed or declared.
//
// image: the contract holds it PIN-PENDING (`x-ocu-reserved`) and the proto
// carries `reserved 6; reserved "image"`, both deferring to ADR-0020 Open
// Question 4 — whether an image ref rides the create surface at all, or is
// resolved deployment-side off the workload trust profile. Removing the field
// would break the shipped BYO-image path, and declaring it would answer a
// gatekeeper question from the implementation side. It stays, annotated, until
// #205 reconciles.
var undeclaredCreateFields = map[string]string{
	"image": "PIN-PENDING per ADR-0020 OQ4; reconciled at " +
		"https://github.com/Wide-Moat/open-computer-use/issues/205",
}

// TestCreateBodyServesOnlyDeclaredFields binds the accepted field set. A field
// the contract withholds is one a reader auditing the document does not know the
// deployment serves.
func TestCreateBodyServesOnlyDeclaredFields(t *testing.T) {
	doc := operatorContract(t)
	schema := schemaOf(t, doc, "CreateRequest")

	declared := map[string]bool{}
	for _, n := range propertyNames(t, schema) {
		declared[n] = true
	}
	for _, name := range jsonNamesOf(t, createBody{}) {
		if declared[name] {
			// An exception that the contract has since declared is stale: it would
			// keep excusing a field that no longer needs excusing, and the next
			// undeclared field could be added beside it without comment.
			if reason, ok := undeclaredCreateFields[name]; ok {
				t.Errorf("%q is now declared by the contract; drop its exception (%s)", name, reason)
			}
			continue
		}
		reason, ok := undeclaredCreateFields[name]
		if !ok {
			t.Errorf("createBody accepts %q, which the contract's CreateRequest does "+
				"not declare — the served surface is wider than the audited one", name)
			continue
		}
		t.Logf("createBody accepts undeclared %q by annotated exception: %s", name, reason)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// allSessionStates enumerates every state a row can reach, so the enum binding
// covers the whole set rather than whichever one a fixture happens to produce.
func allSessionStates() []state.SessionState {
	return []state.SessionState{state.StateReserved, state.StateActive, state.StateReleased}
}

// recordDeny drives the deny writer the routes use and captures what a client
// would receive. It goes through the real writer rather than asserting on a
// string constant: the constant is what drifted from the contract.
func recordDeny(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	writeStatus(rec, http.StatusForbidden, "denied")
	return rec
}
