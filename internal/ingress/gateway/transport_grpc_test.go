// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	sessionv1 "github.com/Wide-Moat/ocu-control/gen/proto/ocu/control/session/v1"
)

// The G1 dual-serve keystone: the GENERATED session-setup gRPC wire serves on
// the SAME mTLS listener as the JSON wire — one socket, one TLS identity, two
// protocols. Create returns the host-derived binding (never the hint), Route
// keys ownership on the host-attested caller (a foreign id is NotFound,
// indistinguishable), Destroy tears the caller's own session down, and the
// privileged operator verbs do not exist on this surface (NFR-SEC-26: the
// absence is the invariant).

func grpcClientFor(t *testing.T, addr string, pair mtlsPair) sessionv1.SessionSetupClient {
	t.Helper()
	creds := credentials.NewTLS(pair.clientTLS)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("grpc client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return sessionv1.NewSessionSetupClient(conn)
}

func createReq(hint string) *sessionv1.CreateRequest {
	return &sessionv1.CreateRequest{
		WorkloadTrustProfile: sessionv1.WorkloadTrustProfile_WORKLOAD_TRUST_PROFILE_TRUSTED_OPERATOR,
		SessionHint:          hint,
		MountIntent:          &sessionv1.MountIntent{Destination: "/data", FilesystemId: "fs-1"},
		EgressPolicy:         &sessionv1.EgressPolicy{DefaultDeny: true, AllowedUpstream: "up:1", FilesystemId: "fs-1"},
		ResourceCaps:         &sessionv1.ResourceCaps{CpuCores: 1, MemoryBytes: 1 << 28},
	}
}

func TestGRPCCreateRouteDestroyOverSharedListener(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-9")
	addr, httpClient := boundGateway(t, pair)
	client := grpcClientFor(t, addr, pair)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	created, err := client.Create(ctx, createReq("hint-9"))
	if err != nil {
		t.Fatalf("grpc Create: %v", err)
	}
	if created.GetSessionId() == "" || created.GetSessionId() == "hint-9" {
		t.Fatalf("session_id = %q; want a host-derived binding, never empty and never "+
			"the caller's hint (NFR-SEC-43)", created.GetSessionId())
	}
	if created.GetControlEndpoint() == "" {
		t.Fatal("create returned no control endpoint")
	}

	routed, err := client.Route(ctx, &sessionv1.RouteRequest{SessionId: "hint-9"})
	if err != nil {
		t.Fatalf("grpc Route of the caller's own session: %v", err)
	}
	if routed.GetControlEndpoint() != created.GetControlEndpoint() {
		t.Fatalf("route endpoint %q != create endpoint %q", routed.GetControlEndpoint(), created.GetControlEndpoint())
	}

	// The JSON wire STILL serves on the same listener: dual-serve, not a
	// replacement — the existing caller keeps working through the migration.
	code, body := gwPost(t, httpClient, addr, "/v1alpha/sessions/status", map[string]any{"session_hint": "hint-9"})
	if code != 200 || body["key"] == "" {
		t.Fatalf("JSON status on the shared listener = %d %v; the gRPC mux broke the JSON wire", code, body)
	}

	if _, err := client.Destroy(ctx, &sessionv1.DestroyRequest{SessionId: "hint-9"}); err != nil {
		t.Fatalf("grpc Destroy: %v", err)
	}
	// The teardown finalizer is host-driven and the row's removal is reconciled
	// asynchronously (nopProvider here), so a synchronous post-destroy lookup is
	// not deterministically NotFound. The DETERMINISTIC guarantee is that a
	// destroy of an id this caller never owned is NotFound — the enumeration
	// boundary — asserted by TestGRPCUnownedSessionIsNotFound.
}

// TestGRPCUnownedSessionIsNotFound: a session id the caller never created
// refuses as NotFound through the gRPC wire — the same enumeration-blocking
// posture the JSON status route holds (NFR-SEC-43), so a caller cannot probe
// for another namespace's sessions by id.
func TestGRPCUnownedSessionIsNotFound(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-a")
	addr, _ := boundGateway(t, pair)
	client := grpcClientFor(t, addr, pair)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Route(ctx, &sessionv1.RouteRequest{SessionId: "never-created"}); status.Code(err) != codes.NotFound {
		t.Fatalf("Route of an unowned id = %v, want NotFound (enumeration blocked, NFR-SEC-43)", err)
	}
	if _, err := client.Destroy(ctx, &sessionv1.DestroyRequest{SessionId: "never-created"}); status.Code(err) != codes.NotFound {
		t.Fatalf("Destroy of an unowned id = %v, want NotFound", err)
	}
}

// TestGRPCUnspecifiedProfileRefused: the closed-enum gate refuses UNSPECIFIED
// fail-closed before any host state is touched.
func TestGRPCUnspecifiedProfileRefused(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-b")
	addr, _ := boundGateway(t, pair)
	client := grpcClientFor(t, addr, pair)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := createReq("h")
	req.WorkloadTrustProfile = sessionv1.WorkloadTrustProfile_WORKLOAD_TRUST_PROFILE_UNSPECIFIED
	_, err := client.Create(ctx, req)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("UNSPECIFIED profile = %v, want InvalidArgument", err)
	}
}

// TestGRPCPrivilegedVerbsAbsent pins NFR-SEC-26 structurally: the service
// exposes EXACTLY Create/Route/Destroy — a force-kill-shaped method does not
// exist, and the refusal is Unimplemented (no such verb), never a
// permission check that implies the verb is there.
func TestGRPCPrivilegedVerbsAbsent(t *testing.T) {
	t.Parallel()
	pair := newMTLSPair(t, "acme", "worker-c")
	addr, _ := boundGateway(t, pair)
	creds := credentials.NewTLS(pair.clientTLS)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, verb := range []string{"ForceKill", "DenylistEdit", "QuotaOverride"} {
		err := conn.Invoke(ctx, "/ocu.control.session.v1.SessionSetup/"+verb,
			&sessionv1.DestroyRequest{}, &sessionv1.DestroyResponse{})
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("%s = %v, want Unimplemented — the privileged verb must not "+
				"exist on this surface (NFR-SEC-26)", verb, err)
		}
	}
}
