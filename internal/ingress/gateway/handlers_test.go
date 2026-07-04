// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestDestroyUnattestedRefused drives the gateway Destroy handler's unattested
// branch: a connection with no verified SAN is refused with ingress.ErrUnattested
// before any host state.
func TestDestroyUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, scope := newTestHandlers(t, gateway.NewCertSANResolver(nil))
	if err := h.Destroy(context.Background(), scope, gatewayConn(), "x"); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Destroy with no verified SAN = %v; want ingress.ErrUnattested", err)
	}
}

// TestStatusUnattestedRefused drives the gateway Status handler's unattested branch.
func TestStatusUnattestedRefused(t *testing.T) {
	t.Parallel()
	h, scope := newTestHandlers(t, gateway.NewCertSANResolver(nil))
	if _, err := h.Status(context.Background(), scope, gatewayConn(), "x"); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Status with no verified SAN = %v; want ingress.ErrUnattested", err)
	}
}

// TestCreateDestroyStatusAttestedHandlers drives the three service handlers with a
// verified-SAN ConnInfo directly (transport-free): a create returns an ACTIVE row,
// a status reads it back, and a destroy tears it down.
func TestCreateDestroyStatusAttestedHandlers(t *testing.T) {
	t.Parallel()
	h, scope := newTestHandlers(t, gateway.NewCertSANResolver(nil))
	ctx := context.Background()
	conn := gatewayConn("acme/worker-7")

	row, err := h.Create(ctx, scope, conn, gateway.CreateRequest{
		Image:       "img",
		SessionHint: "sess",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if row.State != state.StateActive {
		t.Fatalf("Create row state = %v; want ACTIVE", row.State)
	}
	got, err := h.Status(ctx, scope, conn, "sess")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Key != row.Key {
		t.Fatalf("Status key = %q; want %q", got.Key, row.Key)
	}
	if err := h.Destroy(ctx, scope, conn, "sess"); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}

// TestResolverRefusesNonGatewayChannel drives the gateway resolver's non-gateway
// channel refusal: identity is never derived off the gateway channel.
func TestResolverRefusesNonGatewayChannel(t *testing.T) {
	t.Parallel()
	r := gateway.NewCertSANResolver(nil)
	conn := ingress.ConnInfo{Channel: ingress.ChannelOperator, CertSANs: []string{"acme/worker-7"}}
	if _, err := r.Resolve(context.Background(), conn); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve on a non-gateway channel = %v; want ErrUnattested", err)
	}
}

// TestResolverSpiffeWithoutWorkloadPath drives the malformed-spiffe branch: a
// "spiffe://trust-domain" SAN with no workload path is refused, and the resolver
// fails closed.
func TestResolverSpiffeWithoutWorkloadPath(t *testing.T) {
	t.Parallel()
	r := gateway.NewCertSANResolver(nil)
	// No workload path after the trust domain (no '/').
	conn := ingress.ConnInfo{Channel: ingress.ChannelGateway, CertSANs: []string{"spiffe://td.example"}}
	if _, err := r.Resolve(context.Background(), conn); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve of a path-less spiffe SAN = %v; want ErrUnattested", err)
	}
}

// TestResolverEmptyIdentityMapperContinues drives the resolver's empty-identity
// continue branch: a mapper that returns an empty identity for the first SAN and a
// valid one for the second resolves the second, proving the loop tries the next SAN.
func TestResolverEmptyIdentityMapperContinues(t *testing.T) {
	t.Parallel()
	mapper := func(san string) (state.Identity, error) {
		if san == "good/caller" {
			return state.Identity{Tenant: "good", Caller: "caller"}, nil
		}
		return state.Identity{}, nil // empty, no error -> the continue branch
	}
	r := gateway.NewCertSANResolver(mapper)
	conn := ingress.ConnInfo{Channel: ingress.ChannelGateway, CertSANs: []string{"empty-one", "good/caller"}}
	c, err := r.Resolve(context.Background(), conn)
	if err != nil {
		t.Fatalf("Resolve with an empty-then-valid SAN = %v; want the valid identity", err)
	}
	if c.Identity.Tenant != "good" || c.Identity.Caller != "caller" {
		t.Fatalf("resolved identity = %+v; want {good caller}", c.Identity)
	}
}

// TestResolverAllSANsRejectFailsClosed drives the no-SAN-mapped fail-closed branch:
// every verified SAN is malformed, so the resolver refuses with ErrUnattested
// (wrapping ErrNoVerifiedSAN).
func TestResolverAllSANsRejectFailsClosed(t *testing.T) {
	t.Parallel()
	r := gateway.NewCertSANResolver(nil)
	conn := ingress.ConnInfo{Channel: ingress.ChannelGateway, CertSANs: []string{"no-slash-1", "no-slash-2"}}
	if _, e := r.Resolve(context.Background(), conn); !errors.Is(e, ingress.ErrUnattested) || !errors.Is(e, gateway.ErrNoVerifiedSAN) {
		t.Fatalf("Resolve with all-malformed SANs = %v; want ErrUnattested wrapping ErrNoVerifiedSAN", e)
	}
}
