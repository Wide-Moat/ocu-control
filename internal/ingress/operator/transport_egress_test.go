// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"net/http"
	"testing"

	ocuruntime "github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestOperatorTransportCreateCarriesEgressPolicy drives a create through the REAL
// bound operator socket and asserts the wire egress_policy (frozen
// session_setup.proto field names) lands on the SessionSpec the provider receives.
// A deny-default egress is what carries a production create past the provider's
// deny-default precondition; the field never carries a credential.
func TestOperatorTransportCreateCarriesEgressPolicy(t *testing.T) {
	t.Parallel()
	spy := &specRecordingProvider{}
	client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

	code, body := postForText(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "egress-session",
		"image":        "registry.example/ocu-sandbox:v1",
		"egress_policy": map[string]any{
			"default_deny":     true,
			"allowed_upstream": "edge:8450",
			"filesystem_id":    "fs-fleet",
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create with egress_policy = %d (%s); want 201", code, body)
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

// TestOperatorTransportCreateBareBodyStaysZeroEgress pins that a create WITHOUT
// egress_policy still lands 201 and the provider sees the zero EgressPolicy — the
// wire field is optional, and a deployment that omits it gets the neutral default
// the provider then validates (a production provider rejects a non-deny-default
// spec below the wire; the wire just faithfully carries what was sent).
func TestOperatorTransportCreateBareBodyStaysZeroEgress(t *testing.T) {
	t.Parallel()
	spy := &specRecordingProvider{}
	client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

	code, body := postForText(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "no-egress",
		"image":        "img",
	})
	if code != http.StatusCreated {
		t.Fatalf("bare create = %d (%s); want 201", code, body)
	}
	specs := spy.captured()
	if len(specs) != 1 {
		t.Fatalf("Materialize called %d times; want 1", len(specs))
	}
	if got := specs[0].Egress; got != (ocuruntime.EgressPolicy{}) {
		t.Fatalf("bare create spec.Egress = %+v; want the zero EgressPolicy", got)
	}
}

// TestOperatorTransportCreateEgressSmuggledFieldRefused pins custody/strict decode:
// an unknown field inside egress_policy is refused 400 (DisallowUnknownFields), the
// provider never called.
func TestOperatorTransportCreateEgressSmuggledFieldRefused(t *testing.T) {
	t.Parallel()
	spy := &specRecordingProvider{}
	client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

	code, _ := postForText(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint": "smuggler",
		"image":        "img",
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

// TestOperatorTransportCreateRejectsControlPubKey pins the custody keystone: the
// wire create body has NO control_pub_key field — the guest verify key is
// deployment-fixed (host-derived), never a request hint (NFR-SEC-43). A body
// smuggling control_pub_key is refused 400 by the strict decoder, the provider
// never called.
func TestOperatorTransportCreateRejectsControlPubKey(t *testing.T) {
	t.Parallel()
	spy := &specRecordingProvider{}
	client := boundOperatorWithProvider(t, fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}, spy)

	code, _ := postForText(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "smuggle-verifykey",
		"image":           "img",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("create smuggling control_pub_key = %d; want 400 (verify key is not a wire field)", code)
	}
	if n := len(spy.captured()); n != 0 {
		t.Fatalf("Materialize called %d times on a refused create; want 0", n)
	}
}
