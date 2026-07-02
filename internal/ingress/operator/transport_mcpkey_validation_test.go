// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestOperatorTransportMCPKeyCreateMissingFieldsRefused proves the wire refuses
// a create whose tenant or deployment is absent (or empty) with 400, not 503:
// the canon create-request marks both required, and the published A2 record pins
// both with minLength 1, so admitting either empty would mint a record the
// hashed-key-set artifact cannot legally render.
func TestOperatorTransportMCPKeyCreateMissingFieldsRefused(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	cases := map[string]map[string]any{
		"missing deployment": {"tenant": "tenant-x"},
		"missing tenant":     {"deployment": "deploy-x"},
		"empty deployment":   {"tenant": "tenant-x", "deployment": ""},
		"empty tenant":       {"tenant": "", "deployment": "deploy-x"},
	}
	for name, body := range cases {
		code, _ := postJSON(t, client, "/v1alpha/mcp-keys", body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: mcp-key create over the wire = %d; want 400", name, code)
		}
	}
}

// TestOperatorTransportMCPKeyCreateTooLongRefused proves the wire refuses a create
// whose tenant or deployment exceeds the A2 maxLength (256) with 400, not the
// internal-fault 503: the over-long value is a client error, mirroring the
// missing-field case. This pins the maxLength half of the writeMCPKeyError mapping
// through a real request — the mint-layer cap (ErrTenantTooLong/ErrDeploymentTooLong)
// is proven in the mcpkey package, but the ROUTE mapping of those errors to 400 was
// unexercised, so a regression folding them into the default 503 would ship green.
func TestOperatorTransportMCPKeyCreateTooLongRefused(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// 257 runes: one past the A2 maxLength of 256.
	tooLong := strings.Repeat("a", 257)
	cases := map[string]map[string]any{
		"over-long tenant":     {"tenant": tooLong, "deployment": "deploy-x"},
		"over-long deployment": {"tenant": "tenant-x", "deployment": tooLong},
	}
	for name, body := range cases {
		code, _ := postJSON(t, client, "/v1alpha/mcp-keys", body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: mcp-key create over the wire = %d; want 400 (over-long is a client error, not a 503 internal fault)", name, code)
		}
	}
}

// TestOperatorTransportRejectsUnknownBodyField proves the operator decode path is
// strict: a request body carrying a field the handler's struct does not declare is
// refused with 400, never silently accepted. This is the first line of defence for
// the authority-hint invariant (NFR-SEC-43): the create/revoke bodies deliberately
// carry NO acting-identity field, so a body cannot supply one — but that guarantee
// rests on DisallowUnknownFields rejecting any extra field. Without this pin a
// refactor dropping the strict-decode would let a body smuggle unexpected fields,
// silently accepted and ignored today but a standing hazard the moment one is wired
// into a handler. The refusal is asserted on every write route that decodes a body.
func TestOperatorTransportRejectsUnknownBodyField(t *testing.T) {
	t.Parallel()
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	_, client, _ := boundOperator(t, resolver, nil)

	// Each route decodes a distinct body; a bogus extra field ("tenant" is a
	// deliberately identity-shaped smuggle attempt) must be rejected on all of them.
	cases := map[string]struct {
		path string
		body map[string]any
	}{
		"create session":  {"/v1alpha/sessions", map[string]any{"session_hint": "s", "tenant": "evil"}},
		"destroy session": {"/v1alpha/sessions/destroy", map[string]any{"session_hint": "s", "tenant": "evil"}},
		"revoke one":      {"/v1alpha/revoke/one", map[string]any{"key": "k", "reason": "r", "tenant": "evil"}},
		"revoke all":      {"/v1alpha/revoke/all", map[string]any{"reason": "r", "tenant": "evil"}},
		"resume all":      {"/v1alpha/resume/all", map[string]any{"reason": "r", "tenant": "evil"}},
		"mcp-key create":  {"/v1alpha/mcp-keys", map[string]any{"tenant": "t", "deployment": "d", "caller": "evil"}},
		"mcp-key revoke":  {"/v1alpha/mcp-keys/revoke", map[string]any{"key_id": "k", "reason": "r", "caller": "evil"}},
	}
	for name, c := range cases {
		code, _ := postJSON(t, client, c.path, c.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: request with an unknown body field = %d; want 400 (strict decode must reject an undeclared field)", name, code)
		}
	}
}
