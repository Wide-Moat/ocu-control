// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"net/http"
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
