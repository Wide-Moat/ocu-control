// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/admit"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fakeAdmitMetrics records the SEC-55 admission-reject counts so a test can assert
// the middleware incremented the right counter on a shed vs a throttle.
type fakeAdmitMetrics struct {
	shed      int
	throttled int
}

func (f *fakeAdmitMetrics) IncAdmissionShed()      { f.shed++ }
func (f *fakeAdmitMetrics) IncAdmissionThrottled() { f.throttled++ }

// reqAs builds an operator request whose host-attested PeerCred carries the given
// uid, stamped on the context exactly as the ConnContext hook does, so the
// admission middleware's callerRateKey resolves a distinct per-caller bucket.
func reqAs(method, path string, uid uint32) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	info := ingress.ConnInfo{Channel: ingress.ChannelOperator, PeerCred: &ingress.PeerCred{UID: uid}}
	return r.WithContext(context.WithValue(r.Context(), connInfoKey{}, info))
}

// TestAdmissionGate_RevokeAdmitsWhileGeneralSaturatedShedsCreate is the SEC-55
// transport keystone: with the single general slot held by an in-flight request,
// a concurrent create (ClassGeneral) is SHED with 503 after the admit wait, while a
// concurrent revoke (ClassPriority) admits from the reserved pool and reaches its
// handler. This is the DoS guarantee at the middleware boundary, not just the gate:
// a create flood on the operator socket cannot starve a revoke.
func TestAdmissionGate_RevokeAdmitsWhileGeneralSaturatedShedsCreate(t *testing.T) {
	t.Parallel()
	l := &Listener{
		gate:      admit.NewGate(1, 1), // 1 general, 1 reserved
		admitWait: 80 * time.Millisecond,
	}

	// A handler that blocks until released, so the in-flight request keeps holding
	// its slot for the duration of the test.
	hold := make(chan struct{})
	var reached sync.Map // path -> struct{}, records which routes reached the handler
	handler := l.admissionGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(r.URL.Path, struct{}{})
		if r.URL.Path == "/hold" {
			<-hold // occupy the single general slot until released
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Occupy the sole general slot with a long-lived general request.
	occupied := make(chan struct{})
	go func() {
		rr := httptest.NewRecorder()
		close(occupied)
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/hold", nil))
	}()
	<-occupied
	// Give the occupier time to actually acquire the slot before we probe.
	waitFor(t, func() bool { _, ok := reached.Load("/hold"); return ok })

	// A create (general) now finds no general slot and is shed with 503 after the wait.
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, httptest.NewRequest(http.MethodPost, "/v1alpha/sessions", nil))
	if createRR.Code != http.StatusServiceUnavailable {
		t.Errorf("create under general saturation got %d, want 503 (load-shed)", createRR.Code)
	}
	if createRR.Header().Get("Retry-After") == "" {
		t.Error("a shed request carries no Retry-After header")
	}
	if _, ok := reached.Load("/v1alpha/sessions"); ok {
		t.Error("a shed create still reached the handler; the gate did not shed it")
	}

	// A revoke (priority) admits from the reserved pool despite the general saturation.
	revokeRR := httptest.NewRecorder()
	handler.ServeHTTP(revokeRR, httptest.NewRequest(http.MethodPost, "/v1alpha/revoke/one", nil))
	if revokeRR.Code != http.StatusOK {
		t.Errorf("revoke under general saturation got %d, want 200 (reserved admit) — SEC-55 violated", revokeRR.Code)
	}
	if _, ok := reached.Load("/v1alpha/revoke/one"); !ok {
		t.Error("the revoke did not reach its handler — it was starved by the general flood")
	}

	close(hold) // release the occupier
}

// TestClassOf_PriorityAndGeneralPartition pins the route classification: the
// kill-switch family and the liveness endpoints are ClassPriority; every other
// operator route is ClassGeneral. A misclassified revoke would lose its reserved
// headroom (starvation) and a misclassified create would steal it.
func TestClassOf_PriorityAndGeneralPartition(t *testing.T) {
	t.Parallel()
	priority := []string{
		"/v1alpha/revoke/one",
		"/v1alpha/revoke/all",
		"/v1alpha/resume/all",
		"/healthz",
		"/metrics",
	}
	general := []string{
		"/v1alpha/sessions",
		"/v1alpha/sessions/destroy",
		"/v1alpha/sessions/abc",
		"/v1alpha/deployment",
		"/v1alpha/mcp-keys",
		"/v1alpha/mcp-keys/revoke", // an mcp-key revoke is NOT a session kill-switch
	}
	for _, p := range priority {
		if got := classOf(p); got != admit.ClassPriority {
			t.Errorf("classOf(%q) = %v, want ClassPriority", p, got)
		}
	}
	for _, p := range general {
		if got := classOf(p); got != admit.ClassGeneral {
			t.Errorf("classOf(%q) = %v, want ClassGeneral", p, got)
		}
	}
}

// TestAdmissionGate_PerCallerRateThrottlesFloodNotCoTenantNorRevoke is the SEC-55
// fairness keystone at the middleware: a single caller flooding GENERAL requests is
// throttled with 429 once over its per-caller rate, while (a) a co-tenant caller
// keeps its full allowance and (b) a REVOKE from the throttled caller still admits —
// the kill switch is never rate-throttled.
func TestAdmissionGate_PerCallerRateThrottlesFloodNotCoTenantNorRevoke(t *testing.T) {
	t.Parallel()
	l := &Listener{
		gate:      admit.NewGate(64, 8), // ample concurrency: the rate limiter is the subject here
		admitWait: time.Second,
		limiter:   admit.NewLimiter(2, time.Minute, state.SystemClock()), // 2 general reqs/caller/min
	}
	handler := l.admissionGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	const flooder, cotenant = uint32(1001), uint32(2002)

	// The flooder's first 2 general requests admit; the 3rd is throttled 429.
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, reqAs(http.MethodPost, "/v1alpha/sessions", flooder))
		if rr.Code != http.StatusOK {
			t.Fatalf("flooder general request %d got %d, want 200", i, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, reqAs(http.MethodPost, "/v1alpha/sessions", flooder))
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("flooder's over-rate general request got %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("a throttled request carries no Retry-After header")
	}

	// The co-tenant is untouched: its general requests still admit.
	for i := 0; i < 2; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, reqAs(http.MethodPost, "/v1alpha/sessions", cotenant))
		if rr.Code != http.StatusOK {
			t.Errorf("co-tenant general request %d got %d, want 200 (the flood consumed a shared bucket)", i, rr.Code)
		}
	}

	// A REVOKE from the throttled flooder still admits — the kill switch is exempt
	// from the per-caller rate limit.
	revokeRR := httptest.NewRecorder()
	handler.ServeHTTP(revokeRR, reqAs(http.MethodPost, "/v1alpha/revoke/one", flooder))
	if revokeRR.Code != http.StatusOK {
		t.Errorf("revoke from a rate-throttled caller got %d, want 200 — the kill switch must not be rate-limited", revokeRR.Code)
	}
}

// TestAdmissionGate_CountsShedAndThrottleDistinctly pins the SEC-55 observability
// wiring: a 429 throttle increments the throttled counter (not shed), and a 503
// shed increments the shed counter (not throttled). Without distinct counting an
// operator cannot tell an undersized pool (shed) from a single hammering caller
// (throttle).
func TestAdmissionGate_CountsShedAndThrottleDistinctly(t *testing.T) {
	t.Parallel()

	// Throttle case: a 1-req/min per-caller limiter, ample pool.
	mxT := &fakeAdmitMetrics{}
	lt := &Listener{
		gate:      admit.NewGate(64, 8),
		admitWait: time.Second,
		limiter:   admit.NewLimiter(1, time.Minute, state.SystemClock()),
		admitMx:   mxT,
	}
	ht := lt.admissionGate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	ht.ServeHTTP(httptest.NewRecorder(), reqAs(http.MethodPost, "/v1alpha/sessions", 7)) // admits (first in window)
	ht.ServeHTTP(httptest.NewRecorder(), reqAs(http.MethodPost, "/v1alpha/sessions", 7)) // throttled 429
	if mxT.throttled != 1 {
		t.Errorf("throttled count = %d, want 1", mxT.throttled)
	}
	if mxT.shed != 0 {
		t.Errorf("shed count = %d on a throttle, want 0 (a throttle is not a shed)", mxT.shed)
	}

	// Shed case: a size-1 general pool held by a blocking request; limiter disabled so
	// the reject is a pool shed, not a rate throttle.
	mxS := &fakeAdmitMetrics{}
	ls := &Listener{
		gate:      admit.NewGate(1, 0),
		admitWait: 60 * time.Millisecond,
		limiter:   admit.NewLimiter(-1, time.Second, state.SystemClock()), // disabled
		admitMx:   mxS,
	}
	hold := make(chan struct{})
	var reached sync.Map
	hs := ls.admissionGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(r.URL.Path, struct{}{})
		if r.URL.Path == "/hold" {
			<-hold
		}
		w.WriteHeader(http.StatusOK)
	}))
	occ := make(chan struct{})
	go func() {
		close(occ)
		hs.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/hold", nil))
	}()
	<-occ
	waitFor(t, func() bool { _, ok := reached.Load("/hold"); return ok })
	hs.ServeHTTP(httptest.NewRecorder(), reqAs(http.MethodPost, "/v1alpha/sessions", 9)) // shed 503
	close(hold)
	if mxS.shed != 1 {
		t.Errorf("shed count = %d, want 1", mxS.shed)
	}
	if mxS.throttled != 0 {
		t.Errorf("throttled count = %d on a shed, want 0 (a shed is not a throttle)", mxS.throttled)
	}
}

// waitFor polls cond up to a short deadline; fails the test if it never holds.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition never became true within the deadline")
}
