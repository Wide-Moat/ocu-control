// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package metrics is the control plane's Prometheus exposition surface for the
// admin console (ADR-0022). It is a ZERO-DEPENDENCY hand-rolled exporter: the
// Prometheus text exposition format (version 0.0.4) is small and stable, so the
// control plane emits it directly rather than pulling the prometheus/client_golang
// transitive tree, keeping the "minimal shelf, zero external dependencies" build
// discipline. The Collector holds the process-lifetime counters and the
// reserved->active start-duration histogram; the live counts-by-state are read
// from the registry at scrape time (a gauge reflects the current set, not a
// running tally). Everything here is OBSERVED operational data — no credential, no
// customer payload, no authority is exposed (NFR-SEC-43).
package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// defaultStartBuckets are the reserved->active start-duration histogram bucket
// upper bounds in seconds. They span the range a sandbox bring-up plausibly takes
// (sub-100ms image-cache hits through multi-second cold pulls), so the avg-start
// tile and its tail are both legible. The buckets are cumulative le-bounds in the
// Prometheus convention; +Inf is appended at emit time.
var defaultStartBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// stateGaugeReader is the read port the counts-by-state gauge enumerates at scrape
// time. It is satisfied by *registry.Custodian (EnrichedLiveSessions) — the same
// sole-custodian read the admin list endpoint uses — so the gauge reflects exactly
// the live set the console lists. A scrape-time read failure yields no gauge
// samples rather than a stale or guessed count (fail-quiet on the metrics path,
// never fail-closed — a scrape must not deny anything).
type stateGaugeReader interface {
	EnrichedLiveSessions(ctx context.Context) ([]state.EnrichedSessionRow, error)
}

// Collector holds the control plane's metrics. The counters and the histogram are
// process-lifetime running tallies guarded by mu; the counts-by-state gauge is
// computed at scrape time from the reader. It is safe for concurrent use: lifecycle
// goroutines increment counters while a scrape reads them.
type Collector struct {
	reader  stateGaugeReader
	buckets []float64

	mu sync.Mutex
	// createsTotal / destroysTotal are monotonic process-lifetime counters.
	createsTotal  uint64
	destroysTotal uint64
	// startBucketCounts[i] is the count of start-durations <= buckets[i] (filled
	// cumulatively at emit). startCount and startSum drive the histogram's _count
	// and _sum and thus the average (sum/count = avg start seconds).
	startBucketCounts []uint64
	startCount        uint64
	startSum          float64
}

// NewCollector builds a Collector reading live state through reader (the registry
// enriched read) with the default start-duration buckets.
func NewCollector(reader stateGaugeReader) *Collector {
	return &Collector{
		reader:            reader,
		buckets:           defaultStartBuckets,
		startBucketCounts: make([]uint64, len(defaultStartBuckets)),
	}
}

// IncCreate records a successful session create.
func (c *Collector) IncCreate() {
	c.mu.Lock()
	c.createsTotal++
	c.mu.Unlock()
}

// IncDestroy records a successful session destroy.
func (c *Collector) IncDestroy() {
	c.mu.Lock()
	c.destroysTotal++
	c.mu.Unlock()
}

// ObserveStart records one reserved->active start duration into the histogram. A
// negative duration (a clock anomaly) is clamped to zero so a setback can never
// push the sum below the count's floor; the value still counts so the count stays
// truthful. This is the source the avg-start-time tile derives from
// (sum/count), NOT a per-row field (ADR-0022).
func (c *Collector) ObserveStart(d time.Duration) {
	secs := d.Seconds()
	if secs < 0 {
		secs = 0
	}
	c.mu.Lock()
	c.startCount++
	c.startSum += secs
	for i, ub := range c.buckets {
		if secs <= ub {
			c.startBucketCounts[i]++
		}
	}
	c.mu.Unlock()
}

// countsByState reads the live set and tallies it by lowercase state name. A read
// failure returns a nil map (no gauge samples emitted) — a scrape never denies or
// guesses. Released rows are not in the live enriched set, so the gauge reports
// reserved and active only.
func (c *Collector) countsByState(ctx context.Context) map[string]uint64 {
	rows, err := c.reader.EnrichedLiveSessions(ctx)
	if err != nil {
		return nil
	}
	out := map[string]uint64{"reserved": 0, "active": 0}
	for _, row := range rows {
		switch row.State {
		case state.StateReserved:
			out["reserved"]++
		case state.StateActive:
			out["active"]++
		}
	}
	return out
}

// ContentType is the Prometheus text exposition content type (version 0.0.4) the
// handler sets so a scraper parses the body correctly.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Handler returns the http.Handler that serves the Prometheus exposition at
// /metrics. It is GET-only (the caller mounts it method-scoped); the body is the
// full metric set computed at scrape time. The handler reads live state through
// the collector's reader, so a scrape reflects the current session set. It is the
// plain-http.Handler the operator listener mounts, keeping the operator package
// decoupled from this collector.
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		c.WritePrometheus(r.Context(), w)
	})
}

// WritePrometheus emits the full metric set in the Prometheus text exposition
// format (version 0.0.4): the counts-by-state gauge (read live at scrape), the
// create/destroy counters, and the reserved->active start-duration histogram. The
// histogram's _sum/_count give the average start tile (avg = sum/count). Each
// metric carries a HELP and TYPE line. The counter snapshot and histogram are read
// under the lock once into locals, then formatted without the lock held, so a
// concurrent increment never tears a sample.
func (c *Collector) WritePrometheus(ctx context.Context, w writer) {
	counts := c.countsByState(ctx)

	c.mu.Lock()
	creates := c.createsTotal
	destroys := c.destroysTotal
	startCount := c.startCount
	startSum := c.startSum
	bucketCounts := make([]uint64, len(c.startBucketCounts))
	copy(bucketCounts, c.startBucketCounts)
	buckets := c.buckets
	c.mu.Unlock()

	// Counts-by-state gauge. Emit reserved/active deterministically (sorted) so the
	// output is byte-stable for a golden test even though the map iteration order is
	// not. When the read failed (counts == nil) the gauge HELP/TYPE still print with
	// no samples, so a scraper sees the series exists but is momentarily empty.
	writeln(w, "# HELP ocu_control_sessions Current live sessions by lifecycle state.")
	writeln(w, "# TYPE ocu_control_sessions gauge")
	if counts != nil {
		names := make([]string, 0, len(counts))
		for name := range counts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(w, "ocu_control_sessions{state=%q} %d\n", name, counts[name])
		}
	}

	// Create/destroy counters.
	writeln(w, "# HELP ocu_control_session_creates_total Sessions successfully created.")
	writeln(w, "# TYPE ocu_control_session_creates_total counter")
	fmt.Fprintf(w, "ocu_control_session_creates_total %d\n", creates)
	writeln(w, "# HELP ocu_control_session_destroys_total Sessions successfully destroyed.")
	writeln(w, "# TYPE ocu_control_session_destroys_total counter")
	fmt.Fprintf(w, "ocu_control_session_destroys_total %d\n", destroys)

	// Reserved->active start-duration histogram. Buckets are cumulative le-bounds;
	// +Inf equals _count. avg start = _sum / _count.
	writeln(w, "# HELP ocu_control_session_start_seconds Reserved->active start duration in seconds.")
	writeln(w, "# TYPE ocu_control_session_start_seconds histogram")
	for i, ub := range buckets {
		fmt.Fprintf(w, "ocu_control_session_start_seconds_bucket{le=%q} %d\n", formatBucket(ub), bucketCounts[i])
	}
	fmt.Fprintf(w, "ocu_control_session_start_seconds_bucket{le=\"+Inf\"} %d\n", startCount)
	fmt.Fprintf(w, "ocu_control_session_start_seconds_sum %s\n", formatFloat(startSum))
	fmt.Fprintf(w, "ocu_control_session_start_seconds_count %d\n", startCount)
}

// writer is the minimal sink WritePrometheus emits to (an http.ResponseWriter or a
// bytes.Buffer in a test). It is io.Writer plus nothing — kept narrow so the
// exposition has no transport coupling.
type writer interface {
	Write(p []byte) (int, error)
}

// writeln writes s followed by a newline, discarding the error (an exposition
// write to a closed scrape connection is not actionable here).
func writeln(w writer, s string) {
	_, _ = w.Write([]byte(s))
	_, _ = w.Write([]byte("\n"))
}

// formatBucket renders a bucket upper bound the way the Prometheus text format
// expects (a plain decimal, no trailing zeros beyond what's needed).
func formatBucket(ub float64) string {
	return formatFloat(ub)
}

// formatFloat renders a float in the shortest round-trippable decimal form, which
// the Prometheus text format accepts and which keeps the golden output stable.
func formatFloat(f float64) string {
	return fmt.Sprintf("%g", f)
}
