// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build linux

package operator_test

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
)

// TestOperatorTransportRealPeerCredResolverEndToEnd wires the PRODUCTION
// PeerCredResolver through the real bound socket and asserts the kernel-attested uid
// flows all the way to the derived owner identity. Every other transport test injects
// a fixedResolver that ignores the connection's PeerCred, so the production identity
// chain — ConnContext -> connCredOf -> peerCredOf (SO_PEERCRED) -> PeerCredResolver
// -> host-derived identity — is exercised only piecewise (peerCredOf in isolation,
// PeerCredResolver against a synthetic conn), never end-to-end over a socket. A
// defect in the glue (ConnContext stashing the wrong PeerCred, connInfoFromRequest
// reading the wrong key) would leave every fixedResolver test green while the live
// listener attested wrongly.
//
// Linux-only: SO_PEERCRED exists only on Linux, so this is the one platform where the
// real resolver derives a genuine identity over a socket. It drives a create with the
// default resolver (NewPeerCredResolver(nil)) and reads the session list back; the
// owner's caller principal must be uid:<this process's uid>, the host-derived binding
// the default UID map produces from the kernel-attested credential.
func TestOperatorTransportRealPeerCredResolverEndToEnd(t *testing.T) {
	t.Parallel()
	// The REAL operator resolver — not fixedResolver. A nil UIDMapper selects the
	// default host-derived mapping (tenant ocu-operator, caller uid:<attested uid>).
	resolver := operator.NewPeerCredResolver(nil)
	client, _ := readEnabledOperator(t, resolver, operator.DeploymentInfo{RuntimeTier: "runc", RuntimeProvider: "docker"})

	// A create over the socket: the connecting peer is this test process, so the
	// kernel attests this process's uid. If the production chain is wired correctly
	// the create is admitted (a create by an unattested caller would be 401).
	code, _ := postJSON(t, client, "/v1alpha/sessions", map[string]any{
		"session_hint":    "peercred-e2e",
		"image":           "ocu/sandbox:test",
		"control_pub_key": make([]byte, 32),
	})
	if code != http.StatusCreated {
		t.Fatalf("create with the real peer-cred resolver over a socket = %d; want 201 (the kernel-attested caller must be admitted end-to-end)", code)
	}

	// Read the live session back and confirm the owner is the host-derived identity
	// the real resolver produced from the kernel-attested uid — proving the uid
	// flowed through ConnContext/connCredOf/peerCredOf/PeerCredResolver, not a stub.
	resp, err := client.Get("http://unix/v1alpha/sessions")
	if err != nil {
		t.Fatalf("GET sessions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET sessions: want 200, got %d", resp.StatusCode)
	}
	var views []operator.SessionView
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatalf("decode views: %v", err)
	}
	if len(views) == 0 {
		t.Fatal("want >=1 live session view after create, got 0")
	}
	wantCaller := "uid:" + strconv.Itoa(os.Getuid())
	v := views[0]
	if v.Owner.Tenant != "ocu-operator" {
		t.Errorf("owner tenant via the real resolver = %q, want ocu-operator", v.Owner.Tenant)
	}
	if v.Owner.Caller != wantCaller {
		t.Errorf("owner caller via the real resolver = %q, want %q (the kernel-attested uid must flow end-to-end)", v.Owner.Caller, wantCaller)
	}
}
