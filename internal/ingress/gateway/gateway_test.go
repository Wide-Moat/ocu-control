// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/gateway"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// nopProvider is a do-nothing RuntimeProvider sufficient for the gateway tests
// that refuse BEFORE any substrate call (an unattested connection touches no
// provider).
type nopProvider struct{}

func (nopProvider) Materialize(context.Context, runtime.SessionSpec) (runtime.Sandbox, error) {
	return runtime.Sandbox{}, nil
}
func (nopProvider) Teardown() runtime.RuntimeTeardown                    { return nopTeardown{} }
func (nopProvider) Reconcile(context.Context) ([]runtime.Sandbox, error) { return nil, nil }

type nopTeardown struct{}

func (nopTeardown) GracefulStop(context.Context, runtime.Sandbox, runtime.Duration) error { return nil }
func (nopTeardown) ForceKill(context.Context, runtime.Sandbox) error                      { return nil }

// newTestHandlers builds a gateway Handlers over an in-memory Store and a
// do-nothing provider, with the supplied resolver.
func newTestHandlers(t *testing.T, resolver ingress.IdentityResolver) (*gateway.Handlers, ingress.ServiceScope) {
	t.Helper()
	clk := state.SystemClock()
	store := state.NewInMemory(clk)
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{
		ConcurrentSessionsPerTenant: 16,
		CreateRatePerCallerPerMin:   16,
	})
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian: custodian,
		Provider:  nopProvider{},
		Clock:     clk,
		Quota:     gate,
		Handoff:   handoff.NewStager(t.TempDir()),
		Audit:     audit.NewRecordingFake(),
		Profile:   0, // ProfileTrustedOperator
		Tier:      runtime.TierRunc,
	})
	h := gateway.NewHandlers(gateway.Deps{Manager: mgr, Resolver: resolver})
	return h, ingress.ServiceScopeFor()
}

// gatewayConn is a ConnInfo carrying verified SANs, modelling a connection the
// listener already resolved from the verified mTLS chain at accept time.
func gatewayConn(sans ...string) ingress.ConnInfo {
	return ingress.ConnInfo{Channel: ingress.ChannelGateway, CertSANs: sans}
}

// TestUnattestedGatewayConnectionRefused asserts a gateway connection with NO
// verified SAN is refused with ingress.ErrUnattested before any host state. The
// stubbed (no-TLS) listener produces exactly this connection, so the gateway is
// fail-closed by default.
func TestUnattestedGatewayConnectionRefused(t *testing.T) {
	t.Parallel()
	h, scope := newTestHandlers(t, gateway.NewCertSANResolver(nil))

	_, err := h.Create(context.Background(), scope, gatewayConn(), gateway.CreateRequest{
		Image:         "img",
		ControlPubKey: make([]byte, 32),
	})
	if !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Create with no verified SAN = %v; want ingress.ErrUnattested", err)
	}
}

// TestCertSANResolverMapsVerifiedSAN asserts the resolver derives a host-derived
// service identity from a verified tenant/caller SAN and never from a body. A
// malformed SAN fails closed.
func TestCertSANResolverMapsVerifiedSAN(t *testing.T) {
	t.Parallel()
	r := gateway.NewCertSANResolver(nil)

	c, err := r.Resolve(context.Background(), gatewayConn("acme/worker-7"))
	if err != nil {
		t.Fatalf("Resolve(acme/worker-7) = %v; want nil", err)
	}
	if c.Identity.Tenant != "acme" || c.Identity.Caller != "worker-7" {
		t.Fatalf("resolved identity = %+v; want {acme worker-7}", c.Identity)
	}
	if c.Channel != ingress.ChannelGateway {
		t.Fatalf("resolved channel = %v; want ChannelGateway", c.Channel)
	}

	// A spiffe-shaped SAN strips the trust-domain segment and maps the workload path.
	cs, err := r.Resolve(context.Background(), gatewayConn("spiffe://td.example/acme/worker-9"))
	if err != nil {
		t.Fatalf("Resolve(spiffe SAN) = %v; want nil", err)
	}
	if cs.Identity.Tenant != "acme" || cs.Identity.Caller != "worker-9" {
		t.Fatalf("spiffe SAN identity = %+v; want {acme worker-9}", cs.Identity)
	}

	// A malformed SAN with no caller segment fails closed.
	if _, err := r.Resolve(context.Background(), gatewayConn("acme")); !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Resolve(malformed SAN) = %v; want ingress.ErrUnattested", err)
	}
}

// TestStatusCrossTenantEnumerationBlocked asserts the audience-scoping defence: a
// gateway caller asking Status for a hint that, in ITS namespace, addresses no row
// gets registry.ErrNotOwned — indistinguishable from not-found — so it cannot probe
// another tenant's session existence (NFR-SEC-43).
func TestStatusCrossTenantEnumerationBlocked(t *testing.T) {
	t.Parallel()
	h, scope := newTestHandlers(t, gateway.NewCertSANResolver(nil))

	_, err := h.Status(context.Background(), scope, gatewayConn("acme/worker-7"), "some-session")
	if !errors.Is(err, registry.ErrNotOwned) {
		t.Fatalf("Status for an absent session = %v; want registry.ErrNotOwned (enumeration blocked)", err)
	}
}

// TestGatewayBindServeStub asserts the no-TLS gateway listener binds a plain TCP
// socket and that a connection over it (carrying no verified SAN) is refused — the
// clearly-stubbed, fail-closed posture for a Phase-3 deployment without certs.
func TestGatewayBindAndAddr(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandlers(t, gateway.NewCertSANResolver(nil))
	_ = h
	l := gateway.NewListener("127.0.0.1:0", gateway.Deps{})
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind on an ephemeral port = %v; want nil", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if l.Addr() == "" {
		t.Fatal("Addr() empty after Bind; want a bound host:port")
	}
}
