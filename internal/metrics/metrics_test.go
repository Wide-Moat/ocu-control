// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package metrics

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// fakeReader is a test stateGaugeReader: it returns the configured enriched rows,
// or the configured error to exercise the fail-quiet scrape path.
type fakeReader struct {
	rows []state.EnrichedSessionRow
	err  error
}

func (f fakeReader) EnrichedLiveSessions(_ context.Context) ([]state.EnrichedSessionRow, error) {
	return f.rows, f.err
}

func row(key string, st state.SessionState) state.EnrichedSessionRow {
	return state.EnrichedSessionRow{SessionRow: state.SessionRow{Key: key, State: st}}
}

// TestExposition_CountersAndGauge asserts the counters increment and the
// counts-by-state gauge reflects the live set, in the Prometheus text format.
func TestExposition_CountersAndGauge(t *testing.T) {
	c := NewCollector(fakeReader{rows: []state.EnrichedSessionRow{
		row("a", state.StateReserved),
		row("b", state.StateActive),
		row("c", state.StateActive),
	}})
	c.IncCreate()
	c.IncCreate()
	c.IncDestroy()

	var buf bytes.Buffer
	c.WritePrometheus(context.Background(), &buf)
	out := buf.String()

	for _, want := range []string{
		`ocu_control_sessions{state="reserved"} 1`,
		`ocu_control_sessions{state="active"} 2`,
		`ocu_control_session_creates_total 2`,
		`ocu_control_session_destroys_total 1`,
		`# TYPE ocu_control_sessions gauge`,
		`# TYPE ocu_control_session_creates_total counter`,
		`# TYPE ocu_control_session_start_seconds histogram`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q\n--- got ---\n%s", want, out)
		}
	}
}

// TestExposition_Histogram asserts the reserved->active histogram records
// durations into the right cumulative buckets and that _sum/_count drive the
// average start (sum/count). Three observations: 0.04s, 0.4s, 2s.
func TestExposition_Histogram(t *testing.T) {
	c := NewCollector(fakeReader{})
	c.ObserveStart(40 * time.Millisecond)  // <= 0.05
	c.ObserveStart(400 * time.Millisecond) // <= 0.5
	c.ObserveStart(2 * time.Second)        // <= 2.5

	var buf bytes.Buffer
	c.WritePrometheus(context.Background(), &buf)
	out := buf.String()

	// 0.04 falls in every bucket >= 0.05; 0.4 in every bucket >= 0.5; 2 in every
	// bucket >= 2.5. So le="0.05" has 1, le="0.5" has 2, le="2.5" has 3.
	for _, want := range []string{
		`ocu_control_session_start_seconds_bucket{le="0.05"} 1`,
		`ocu_control_session_start_seconds_bucket{le="0.5"} 2`,
		`ocu_control_session_start_seconds_bucket{le="2.5"} 3`,
		`ocu_control_session_start_seconds_bucket{le="+Inf"} 3`,
		`ocu_control_session_start_seconds_count 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("histogram missing %q\n--- got ---\n%s", want, out)
		}
	}
	// _sum = 0.04 + 0.4 + 2 = 2.44; avg = 2.44/3 ~= 0.813.
	if !strings.Contains(out, `ocu_control_session_start_seconds_sum 2.44`) {
		t.Errorf("histogram sum line missing or wrong\n--- got ---\n%s", out)
	}
}

// TestExposition_NegativeDurationClampedToZero proves a clock-anomaly negative
// duration counts (so _count stays truthful) but contributes zero to _sum, so a
// setback never pushes the average below the floor.
func TestExposition_NegativeDurationClampedToZero(t *testing.T) {
	c := NewCollector(fakeReader{})
	c.ObserveStart(-5 * time.Second)

	var buf bytes.Buffer
	c.WritePrometheus(context.Background(), &buf)
	out := buf.String()

	if !strings.Contains(out, `ocu_control_session_start_seconds_count 1`) {
		t.Errorf("negative duration must still count\n%s", out)
	}
	if !strings.Contains(out, `ocu_control_session_start_seconds_sum 0`) {
		t.Errorf("negative duration must contribute 0 to sum\n%s", out)
	}
	// It lands in every finite bucket (0 <= every le).
	if !strings.Contains(out, `ocu_control_session_start_seconds_bucket{le="0.05"} 1`) {
		t.Errorf("clamped-to-zero duration must land in the smallest bucket\n%s", out)
	}
}

// TestExposition_ReadFailureEmitsGaugeHeaderNoSamples proves the gauge fails quiet
// on a scrape-time read error: the HELP/TYPE print but no sample lines, so a
// scrape never denies and never reports a guessed count.
func TestExposition_ReadFailureEmitsGaugeHeaderNoSamples(t *testing.T) {
	c := NewCollector(fakeReader{err: state.ErrStoreUnavailable})

	var buf bytes.Buffer
	c.WritePrometheus(context.Background(), &buf)
	out := buf.String()

	if !strings.Contains(out, `# TYPE ocu_control_sessions gauge`) {
		t.Errorf("gauge header must print even on read failure\n%s", out)
	}
	if strings.Contains(out, `ocu_control_sessions{state=`) {
		t.Errorf("a failed read must emit NO gauge samples, got:\n%s", out)
	}
	// The counters and histogram still print (they are process-local, not read).
	if !strings.Contains(out, `ocu_control_session_creates_total 0`) {
		t.Errorf("counters must still print on a gauge read failure\n%s", out)
	}
}

// TestContentType pins the Prometheus exposition content type.
func TestContentType(t *testing.T) {
	if ContentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("ContentType drifted from the Prometheus 0.0.4 exposition type: %q", ContentType)
	}
}
