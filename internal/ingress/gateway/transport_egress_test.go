// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"net/http"
	"testing"

	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestGatewayTransportCreateCarriesEgressPolicy drives a create through the REAL
// mTLS gateway and asserts the wire egress_policy (frozen session_setup.proto
// field names) lands on the SessionSpec the provider receives. The deny-default
// posture is what carries a production create past the provider's deny-default
// precondition.
func TestGatewayTransportCreateCarriesEgressPolicy(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	spy := &specRecordingProvider{}
	addr, client := boundGatewayWithProvider(t, pair, spy)

	code, body := gwPostText(t, client, addr, "/v1alpha/sessions", map[string]any{
		"session_hint":    "egress-mtls",
		"image":           "registry.example/ocu-sandbox:v1",
		"control_pub_key": make([]byte, 32),
		"egress_policy": map[string]any{
			"default_deny":     true,
			"allowed_upstream": "edge:8450",
			"filesystem_id":    "fs-fleet",
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create with egress_policy over mTLS = %d (%s); want 201", code, body)
	}

	specs := spy.captured()
	if len(specs) != 1 {
		t.Fatalf("Materialize called %d times; want 1", len(specs))
	}
	want := ocuruntime.EgressPolicy{
		DefaultDeny:     true,
		AllowedUpstream: "edge:8450",
		FilesystemID:    "fs-fleet",
	}
	if got := specs[0].Egress; got != want {
		t.Fatalf("spec.Egress = %+v; want %+v", got, want)
	}
}

// TestGatewayTransportCreateEgressSmuggledFieldRefused pins strict decode on the
// gateway plane: an unknown field inside egress_policy is refused 400, the provider
// never called.
func TestGatewayTransportCreateEgressSmuggledFieldRefused(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-7")
	spy := &specRecordingProvider{}
	addr, client := boundGatewayWithProvider(t, pair, spy)

	code, _ := gwPostText(t, client, addr, "/v1alpha/sessions", map[string]any{
		"session_hint":    "smuggler-mtls",
		"image":           "img",
		"control_pub_key": make([]byte, 32),
		"egress_policy": map[string]any{
			"default_deny": true,
			"auth_token":   "eyJ.fake.token",
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("egress_policy with an unknown field = %d; want 400", code)
	}
	if n := len(spy.captured()); n != 0 {
		t.Fatalf("Materialize called %d times on a refused create; want 0", n)
	}
}
