// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// The wiring half of #107 on the gateway channel: the per-connection hook must
// stamp what the authentication trail keys on, and NewHandlers must wrap the
// resolver when an emit is supplied — the decorator nobody wires observes
// nothing.

// TestConnContextStampsLatchAndConnID drives the real ConnContext hook off the
// server newServer builds. Without the latch every request would emit a logon;
// without the ConnID two connections' logons are indistinguishable.
func TestConnContextStampsLatchAndConnID(t *testing.T) {
	srv := newServer(context.Background(), http.NewServeMux())
	if srv.ConnContext == nil {
		t.Fatal("the gateway server has no ConnContext hook")
	}

	ctx1 := srv.ConnContext(context.Background(), nil)
	ctx2 := srv.ConnContext(context.Background(), nil)

	if ingress.AuthnLatchFrom(ctx1) == nil {
		t.Error("the per-connection context carries no authn latch; every request " +
			"on the connection would emit its own logon")
	}
	if ingress.AuthnLatchFrom(ctx1) == ingress.AuthnLatchFrom(ctx2) {
		t.Error("two connections share one latch; the second connection's logon " +
			"would be swallowed")
	}

	r1 := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil).WithContext(ctx1)
	r2 := httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil).WithContext(ctx2)
	id1, id2 := connInfoFromRequest(r1).ConnID, connInfoFromRequest(r2).ConnID
	if id1 == "" || id2 == "" {
		t.Fatalf("a hooked connection carries an empty ConnID (%q, %q)", id1, id2)
	}
	if id1 == id2 {
		t.Errorf("two connections share ConnID %q", id1)
	}

	// Same connection, second request: the ConnID must be stable, or the latch
	// keys on nothing and correlation breaks mid-connection.
	again := connInfoFromRequest(httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx1)).ConnID
	if again != id1 {
		t.Errorf("the same connection reported ConnID %q then %q", id1, again)
	}
}

// TestUnhookedRequestCarriesNoConnID keeps the latchless path visible as such:
// a request that did not come through Serve has no connection identity, and
// inventing one would make the fallback indistinguishable from the real path.
func TestUnhookedRequestCarriesNoConnID(t *testing.T) {
	info := connInfoFromRequest(httptest.NewRequest(http.MethodGet, "/x", nil))
	if info.ConnID != "" {
		t.Errorf("an unhooked request carries ConnID %q, want empty", info.ConnID)
	}
}

// TestNewHandlersWrapsTheResolverWhenEmitIsSet is the wiring keystone. The
// decorator exists; if NewHandlers does not apply it, the daemon's emit is a
// function nothing calls and the trail is silently empty.
func TestNewHandlersWrapsTheResolverWhenEmitIsSet(t *testing.T) {
	var mu sync.Mutex
	var recs []ocsf.AuthnRecord
	h := NewHandlers(Deps{
		AuthnEmit: func(_ context.Context, rec ocsf.AuthnRecord) error {
			mu.Lock()
			defer mu.Unlock()
			recs = append(recs, rec)
			return nil
		},
	})

	// An unattested ConnInfo fails resolution; the decorator must record the
	// failure. This drives the wrap through behaviour, not reflection.
	_, err := h.resolver.Resolve(context.Background(), ingress.ConnInfo{Channel: ingress.ChannelGateway})
	if err == nil {
		t.Fatal("an unattested ConnInfo resolved")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(recs) != 1 || recs[0].Outcome != ocsf.AuthnFailure {
		t.Fatalf("the failed resolution emitted %d record(s) (%+v); the resolver is "+
			"not wrapped and the trail is silently empty", len(recs), recs)
	}
}

// TestNewHandlersWithoutEmitStaysBare keeps the tests' seam: injecting a bare
// resolver with no emit must not panic and must not wrap.
func TestNewHandlersWithoutEmitStaysBare(t *testing.T) {
	h := NewHandlers(Deps{})
	if _, ok := h.resolver.(*CertSANResolver); !ok {
		t.Errorf("with no emit the resolver is %T, want the bare default", h.resolver)
	}
}
