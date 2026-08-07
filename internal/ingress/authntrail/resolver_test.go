// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authntrail_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/authntrail"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// The decorator turns identity resolution into the authentication trail
// (#107): one 3002 logon per accepted connection, every failure, fail-open
// with counted loss (NFR-SEC-79). It wraps ingress.IdentityResolver so the
// resolvers stay pure and no handler can forget to emit.

// fakeResolver scripts the underlying resolution.
type fakeResolver struct {
	caller ingress.AuthenticatedCaller
	err    error
	calls  int
}

func (f *fakeResolver) Resolve(_ context.Context, _ ingress.ConnInfo) (ingress.AuthenticatedCaller, error) {
	f.calls++
	if f.err != nil {
		return ingress.AuthenticatedCaller{}, f.err
	}
	return f.caller, nil
}

// collectEmitter captures emitted records; optionally failing to test the
// fail-open path.
type collectEmitter struct {
	mu   sync.Mutex
	recs []ocsf.AuthnRecord
	err  error
}

func (c *collectEmitter) emit(_ context.Context, rec ocsf.AuthnRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.recs = append(c.recs, rec)
	return nil
}

func (c *collectEmitter) records() []ocsf.AuthnRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ocsf.AuthnRecord{}, c.recs...)
}

func okCaller() ingress.AuthenticatedCaller {
	return ingress.AuthenticatedCaller{
		Identity: state.Identity{Tenant: "t9", Caller: "t9/portal-a"},
		Channel:  ingress.ChannelGateway,
	}
}

func gatewayConn(id string) ingress.ConnInfo {
	return ingress.ConnInfo{
		Channel:  ingress.ChannelGateway,
		CertSANs: []string{"spiffe://ocu/t9/portal-a"},
		ConnID:   id,
	}
}

// TestSuccessEmitsOncePerConnection is the granularity ruling. The TLS
// handshake is the authentication act; every request on the connection
// re-reads the same attestation, and emitting per request would fabricate
// authentications that never happened.
func TestSuccessEmitsOncePerConnection(t *testing.T) {
	inner := &fakeResolver{caller: okCaller()}
	em := &collectEmitter{}
	r := authntrail.Wrap(inner, em.emit)

	// One connection, three requests: the latch rides the per-conn context the
	// ConnContext hook creates.
	ctx := ingress.WithAuthnLatch(context.Background())
	conn := gatewayConn("conn-1")
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(ctx, conn); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}

	recs := em.records()
	if len(recs) != 1 {
		t.Fatalf("3 requests on one connection emitted %d logon events, want 1", len(recs))
	}
	if recs[0].Outcome != ocsf.AuthnSuccess || recs[0].ConnID != "conn-1" {
		t.Errorf("emitted %+v; want a success bound to conn-1", recs[0])
	}
	if inner.calls != 3 {
		t.Errorf("the inner resolver ran %d times, want 3 — the decorator must not "+
			"cache resolution, only the emit", inner.calls)
	}
}

// TestTwoConnectionsEmitTwice keeps the latch per-connection, not global. A
// second connection is a second authentication act.
func TestTwoConnectionsEmitTwice(t *testing.T) {
	inner := &fakeResolver{caller: okCaller()}
	em := &collectEmitter{}
	r := authntrail.Wrap(inner, em.emit)

	for i, id := range []string{"conn-1", "conn-2"} {
		ctx := ingress.WithAuthnLatch(context.Background())
		if _, err := r.Resolve(ctx, gatewayConn(id)); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	if got := len(em.records()); got != 2 {
		t.Errorf("two connections emitted %d logon events, want 2", got)
	}
}

// TestEveryFailureEmits is the failure half: no latch, every attempt recorded,
// the cause carried. A mapper-refused SAN is an authentication failure only
// this path sees.
func TestEveryFailureEmits(t *testing.T) {
	inner := &fakeResolver{err: errors.New("SAN not tenant/caller-shaped")}
	em := &collectEmitter{}
	r := authntrail.Wrap(inner, em.emit)

	ctx := ingress.WithAuthnLatch(context.Background())
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(ctx, gatewayConn("conn-1")); err == nil {
			t.Fatal("the decorator swallowed the resolution failure")
		}
	}

	recs := em.records()
	if len(recs) != 3 {
		t.Fatalf("3 failed attempts emitted %d events, want 3 — failures are never "+
			"latched", len(recs))
	}
	for _, rec := range recs {
		if rec.Outcome != ocsf.AuthnFailure {
			t.Errorf("a failure emitted outcome %v", rec.Outcome)
		}
		if rec.FailureDetail == "" {
			t.Error("the failure record carries no cause")
		}
	}
}

// TestEmitFailureIsFailOpen is NFR-SEC-79's producer posture, verbatim canon:
// "a downstream failure neither blocks nor denies … counted, never silently
// lost". A dead audit disk must not take the read surface down — the
// fail-closed anchor is downstream, on the privileged actions themselves.
func TestEmitFailureIsFailOpen(t *testing.T) {
	inner := &fakeResolver{caller: okCaller()}
	em := &collectEmitter{err: errors.New("disk full")}
	r := authntrail.Wrap(inner, em.emit)

	ctx := ingress.WithAuthnLatch(context.Background())
	caller, err := r.Resolve(ctx, gatewayConn("conn-1"))
	if err != nil {
		t.Fatalf("a failed logon EMIT denied the resolution: %v — the fail-closed "+
			"anchor is the privileged action, not the observation", err)
	}
	if caller.Identity.Caller != "t9/portal-a" {
		t.Errorf("the resolved caller was lost: %+v", caller)
	}
	if got := r.Dropped(); got != 1 {
		t.Errorf("dropped counter = %d, want 1 — a loss is counted, never silent", got)
	}
}

// TestFailedEmitDoesNotLatch keeps the latch bound to a RECORDED success. If
// the emit failed, the connection's logon is not in the trail, so the next
// request must try again rather than treat the loss as done.
func TestFailedEmitDoesNotLatch(t *testing.T) {
	inner := &fakeResolver{caller: okCaller()}
	em := &collectEmitter{err: errors.New("disk full")}
	r := authntrail.Wrap(inner, em.emit)

	ctx := ingress.WithAuthnLatch(context.Background())
	if _, err := r.Resolve(ctx, gatewayConn("conn-1")); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// The disk recovers; the next request on the same connection must land the
	// logon that was lost.
	em.mu.Lock()
	em.err = nil
	em.mu.Unlock()
	if _, err := r.Resolve(ctx, gatewayConn("conn-1")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := len(em.records()); got != 1 {
		t.Errorf("after a recovered emit the trail holds %d logons, want 1 — a failed "+
			"emit latched as if it had been recorded", got)
	}
}

// TestProtocolFollowsTheChannel maps the record's protocol from what actually
// authenticated: SANs mean mTLS, PeerCred means the operator socket.
func TestProtocolFollowsTheChannel(t *testing.T) {
	inner := &fakeResolver{caller: okCaller()}
	em := &collectEmitter{}
	r := authntrail.Wrap(inner, em.emit)

	ctx := ingress.WithAuthnLatch(context.Background())
	if _, err := r.Resolve(ctx, gatewayConn("conn-1")); err != nil {
		t.Fatalf("gateway resolve: %v", err)
	}
	ctx2 := ingress.WithAuthnLatch(context.Background())
	op := ingress.ConnInfo{
		Channel:  ingress.ChannelOperator,
		PeerCred: &ingress.PeerCred{UID: 501},
		ConnID:   "conn-2",
	}
	if _, err := r.Resolve(ctx2, op); err != nil {
		t.Fatalf("operator resolve: %v", err)
	}

	recs := em.records()
	if len(recs) != 2 {
		t.Fatalf("emitted %d, want 2", len(recs))
	}
	if recs[0].Protocol != ocsf.AuthnProtocolMTLS || recs[0].CertSAN == "" {
		t.Errorf("the gateway logon reports %q with SAN %q", recs[0].Protocol, recs[0].CertSAN)
	}
	if recs[1].Protocol != ocsf.AuthnProtocolPeerCred || recs[1].CertSAN != "" {
		t.Errorf("the operator logon reports %q with SAN %q; a socket peer must not "+
			"invent a certificate", recs[1].Protocol, recs[1].CertSAN)
	}
}

// TestNoLatchInContextStillEmits covers a request that did not come through a
// ConnContext hook. Resolution on such a request fails attestation anyway in
// practice; if it somehow succeeds, emitting per request is the safe side —
// an extra observation, never a lost one.
func TestNoLatchInContextStillEmits(t *testing.T) {
	inner := &fakeResolver{caller: okCaller()}
	em := &collectEmitter{}
	r := authntrail.Wrap(inner, em.emit)

	if _, err := r.Resolve(context.Background(), gatewayConn("conn-x")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := len(em.records()); got != 1 {
		t.Errorf("a latchless success emitted %d events, want 1", got)
	}
}

// TestConnIDsAreDistinct pins the ingress counter: two stamped connections
// never share an identity, and the zero value stays empty for the latchless
// path to remain visible as such.
func TestConnIDsAreDistinct(t *testing.T) {
	a, b := ingress.NextConnID(), ingress.NextConnID()
	if a == b {
		t.Fatalf("two connections share the id %q", a)
	}
	if a == "" || b == "" {
		t.Fatal("a stamped connection has an empty id")
	}
}
