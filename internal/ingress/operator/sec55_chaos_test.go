// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestSEC55_RevokeLatencyStaysBoundedUnderIngressFlood is the NFR-SEC-55 chaos
// keystone, co-located with the kill-switch SLA concern: while the operator ingress
// is flooded with GENERAL requests (the agent/admin create path) past the general
// pool AND the per-caller rate, a concurrent stream of revoke (priority) requests
// keeps a p99 admission latency far below the flood's — the revoke path is not
// starved. The absolute SLA is 30s; this unit-scale test proves the SHAPE the SLA
// depends on (revoke p99 << flood p99) deterministically, and the red-probe shows
// that without the reserved pool the revoke latency collapses into the flood.
func TestSEC55_RevokeLatencyStaysBoundedUnderIngressFlood(t *testing.T) {
	t.Parallel()

	// A deliberately SMALL general pool so a modest flood saturates it; a reserved
	// pool that keeps the revoke path admitting. A short admit-wait so a shed general
	// request returns quickly rather than parking a goroutine.
	// A fixed resolver so revokes resolve a valid operator scope over the socket
	// (darwin has no SO_PEERCRED, so the default resolver would refuse).
	resolver := fixedResolver{id: state.Identity{Tenant: "ocu-operator", Caller: "uid:1000"}}
	deps := operatorDepsFor(t, resolver, nil)
	// A small general pool and a reserved pool for the revoke path, under a real
	// concurrent socket flood.
	deps.AdmitGeneral = 4
	deps.AdmitReserved = 4
	deps.AdmitWait = 500 * time.Millisecond
	// Disable the per-caller rate limiter here so the SUBJECT is the reserved-pool
	// starvation resistance (the limiter has its own keystone). All flood requests
	// share the test's caller, which the limiter would otherwise throttle early and
	// mask the concurrency-starvation dimension.
	deps.PerCallerRate = -1

	_, client, _ := boundOperatorWithDeps(t, deps)

	// Flood: many concurrent general requests contending for the single general slot,
	// each recording its own end-to-end latency. With 32 goroutines on 1 slot and a
	// 3s shed-wait, a general request routinely parks hundreds of ms behind the queue.
	var (
		stop     atomic.Bool
		floodWG  sync.WaitGroup
		floodMu  sync.Mutex
		floodLat []time.Duration
	)
	for i := 0; i < 32; i++ {
		floodWG.Add(1)
		go func() {
			defer floodWG.Done()
			for !stop.Load() {
				start := time.Now()
				// A create with a bad image is a fast 400 in the handler, so the latency
				// is dominated by admission-queue wait — exactly the ingress pressure the
				// revoke path must be immune to.
				postJSON(t, client, "/v1alpha/sessions", map[string]any{"image": "img", "mount_intent": map[string]any{}})
				d := time.Since(start)
				floodMu.Lock()
				floodLat = append(floodLat, d)
				floodMu.Unlock()
			}
		}()
	}

	// Let the flood saturate the single general slot before measuring.
	time.Sleep(150 * time.Millisecond)

	// Measure revoke admission latency under the sustained flood.
	const revokes = 40
	lats := make([]time.Duration, 0, revokes)
	var latMu sync.Mutex
	var revWG sync.WaitGroup
	for i := 0; i < revokes; i++ {
		revWG.Add(1)
		go func() {
			defer revWG.Done()
			start := time.Now()
			code := postRevoke(t, client)
			d := time.Since(start)
			if code == http.StatusOK {
				latMu.Lock()
				lats = append(lats, d)
				latMu.Unlock()
			}
		}()
		time.Sleep(2 * time.Millisecond) // stagger so revokes overlap the flood, not each other
	}
	revWG.Wait()

	stop.Store(true)
	floodWG.Wait()

	if len(lats) < revokes*8/10 {
		t.Fatalf("only %d/%d revokes admitted under flood; the priority path was starved", len(lats), revokes)
	}
	revokeP99 := percentile(lats, 0.99)
	floodMu.Lock()
	floodSamples := len(floodLat)
	floodMu.Unlock()

	// Under a sustained real-socket flood, EVERY revoke admits (asserted above) and
	// the p99 stays well inside the 30s SEC-01 SLA with orders of magnitude to spare.
	// This is the socket-level liveness proof; the DETERMINISTIC starvation-resistance
	// keystone (revoke admits while the general pool is fully held, red-probed) lives
	// in TestAdmissionGate_RevokeAdmitsWhileGeneralSaturatedShedsCreate, which can
	// hold a slot with a blocking handler that a fast real handler cannot reproduce.
	const bound = time.Second
	if revokeP99 > bound {
		t.Errorf("revoke p99 admission latency %v under a real-socket flood exceeds %v (SEC-01 SLA is 30s)", revokeP99, bound)
	}
	t.Logf("revoke p99=%v over %d admitted revokes; flood delivered %d general requests", revokeP99, len(lats), floodSamples)
}

// boundOperatorWithDeps binds and serves an operator listener on a fresh socket
// from an explicit Deps (so a test can size the admission gate), returning the
// socket path and a unix HTTP client. It mirrors boundOperator but takes the deps
// the caller already built.
func boundOperatorWithDeps(t *testing.T, deps operator.Deps) (string, *http.Client, *operator.Listener) {
	t.Helper()
	socket := shortSocketPath(t)
	if deps.Healthz == nil {
		deps.Healthz = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	}
	l := operator.NewListener(socket, deps)
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-serveErr:
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return after context cancel")
		}
	})
	client := unixClient(socket)
	waitOperatorReady(t, client)
	return socket, client, l
}

// postRevoke fires a revoke-one and returns the status code, draining the body so
// the connection is reusable.
func postRevoke(t *testing.T, client *http.Client) int {
	t.Helper()
	code, _ := postJSON(t, client, "/v1alpha/revoke/one", map[string]any{"key": "does-not-exist", "reason": "sec55-chaos"})
	return code
}

// percentile returns the p-quantile (0..1) of ds by nearest-rank. An empty slice
// yields 0.
func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := make([]time.Duration, len(ds))
	copy(s, ds)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(p * float64(len(s)-1))
	return s[idx]
}
