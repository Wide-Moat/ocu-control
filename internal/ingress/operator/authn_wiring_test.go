// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
)

// The wiring half of #107 on the operator channel, mirroring the gateway's:
// the per-connection hook stamps the latch and the conn identity, and
// NewHandlers wraps the resolver when an emit is supplied.

// TestOperatorConnContextStampsLatchAndConnID drives the hook the operator
// server installs. connCredOf fails on a nil net.Conn, so the hook takes its
// unattested arm — which must STILL stamp the latch and the ConnID: an
// unattested connection's failed resolutions are exactly the records the
// failure half of the trail exists for.
func TestOperatorConnContextStampsLatchAndConnID(t *testing.T) {
	srv := newServer(context.Background(), http.NewServeMux())
	if srv.ConnContext == nil {
		t.Fatal("the operator server has no ConnContext hook")
	}

	ctx1 := srv.ConnContext(context.Background(), nil)
	ctx2 := srv.ConnContext(context.Background(), nil)

	if ingress.AuthnLatchFrom(ctx1) == nil {
		t.Error("the per-connection context carries no authn latch")
	}
	if ingress.AuthnLatchFrom(ctx1) == ingress.AuthnLatchFrom(ctx2) {
		t.Error("two connections share one latch")
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
}

// TestOperatorNewHandlersWrapsTheResolverWhenEmitIsSet is the same keystone as
// the gateway's: an emit nothing calls is a trail that is silently empty.
func TestOperatorNewHandlersWrapsTheResolverWhenEmitIsSet(t *testing.T) {
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

	_, err := h.resolver.Resolve(context.Background(), ingress.ConnInfo{Channel: ingress.ChannelOperator})
	if err == nil {
		t.Fatal("an unattested ConnInfo resolved")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(recs) != 1 || recs[0].Outcome != ocsf.AuthnFailure {
		t.Fatalf("the failed resolution emitted %d record(s); the resolver is not "+
			"wrapped", len(recs))
	}
	if recs[0].Protocol != ocsf.AuthnProtocolPeerCred {
		t.Errorf("the operator failure reports protocol %q, want the socket's own", recs[0].Protocol)
	}
}

// TestOperatorNewHandlersWithoutEmitStaysBare keeps the unit-test seam.
func TestOperatorNewHandlersWithoutEmitStaysBare(t *testing.T) {
	h := NewHandlers(Deps{})
	if _, ok := h.resolver.(*PeerCredResolver); !ok {
		t.Errorf("with no emit the resolver is %T, want the bare default", h.resolver)
	}
}
