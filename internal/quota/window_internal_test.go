// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package quota

import (
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestMinuteWindowDerivation pins the per-minute label: UTC, truncated to the
// minute, timezone-free, and identical for any instant within the same minute.
func TestMinuteWindowDerivation(t *testing.T) {
	t.Parallel()
	base := time.Date(2025, time.March, 4, 5, 6, 7, 890_000_000, time.UTC)
	clk := state.NewFakeClock(base)

	got := minuteWindow(clk)
	const want = "2025-03-04T05:06Z"
	if got != want {
		t.Fatalf("minuteWindow = %q, want %q", got, want)
	}

	// Any instant within the same minute yields the same label.
	clk.SetWallClock(base.Add(52 * time.Second))
	if got2 := minuteWindow(clk); got2 != want {
		t.Fatalf("minuteWindow within same minute = %q, want %q", got2, want)
	}

	// The next minute yields a different, later label.
	clk.SetWallClock(base.Add(1 * time.Minute))
	if got3 := minuteWindow(clk); got3 == want {
		t.Fatalf("minuteWindow in next minute = %q, want a different bucket", got3)
	}
}

// TestMinuteWindowNormalizesToUTC proves a non-UTC clock reading is normalized to
// UTC before truncation, so the label is timezone-free and identical across
// backends regardless of the host zone.
func TestMinuteWindowNormalizesToUTC(t *testing.T) {
	t.Parallel()
	// 05:06 in a +02:00 zone is 03:06 UTC.
	zone := time.FixedZone("test+2", 2*60*60)
	base := time.Date(2025, time.March, 4, 5, 6, 0, 0, zone)
	clk := state.NewFakeClock(base)

	got := minuteWindow(clk)
	const want = "2025-03-04T03:06Z"
	if got != want {
		t.Fatalf("minuteWindow (non-UTC input) = %q, want %q", got, want)
	}
}

// TestDayWindowDerivation pins the per-day label: UTC, truncated to the day,
// timezone-free, and identical for any instant within the same UTC day.
func TestDayWindowDerivation(t *testing.T) {
	t.Parallel()
	base := time.Date(2025, time.March, 4, 5, 6, 7, 0, time.UTC)
	clk := state.NewFakeClock(base)

	got := dayWindow(clk)
	const want = "2025-03-04Z"
	if got != want {
		t.Fatalf("dayWindow = %q, want %q", got, want)
	}

	// Later the same UTC day yields the same label.
	clk.SetWallClock(base.Add(18 * time.Hour))
	if got2 := dayWindow(clk); got2 != want {
		t.Fatalf("dayWindow same day = %q, want %q", got2, want)
	}

	// The next UTC day yields a different label.
	clk.SetWallClock(base.Add(24 * time.Hour))
	if got3 := dayWindow(clk); got3 == want {
		t.Fatalf("dayWindow next day = %q, want a different bucket", got3)
	}
}
