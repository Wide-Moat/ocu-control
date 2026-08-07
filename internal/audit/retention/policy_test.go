// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"errors"
	"testing"
	"time"
)

// NFR-COMP-01 fixes the retention floor at 7 years by default, configurable to
// 10, two-tier hot (<=90d) -> cold, and says plainly: "The retention floor is
// mandatory on both shelves; only the WORM substrate is shelf-conditional."
//
// ADR-0009 puts retention-policy ENFORCEMENT on OCU's build side; the WORM store
// is a customer seam. So this package decides what may be removed and when. It
// removes nothing itself and knows nothing about a substrate.
//
// The floor is a MINIMUM. Every regulator behind NFR-COMP-01 specifies how long
// records must be kept, never when they must be destroyed, so the load-bearing
// property is the refusal of a premature deletion — not the performance of a
// timely one.

// TestFloorIsSevenYearsByDefault pins the default. A deployment that configures
// nothing is the one most likely to be audited against the regulation.
func TestFloorIsSevenYearsByDefault(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy(zero): %v", err)
	}
	if got := p.Floor(); got != DefaultFloor {
		t.Errorf("default floor = %v, want %v (7 years)", got, DefaultFloor)
	}
	// Stated in years so a wrong constant is visible here, not only as a Duration.
	if years := DefaultFloor.Hours() / 24 / 365; years < 6.9 || years > 7.1 {
		t.Errorf("DefaultFloor is %.2f years, want 7", years)
	}
}

// TestFloorIsConfigurableUpwardOnly is the clamp. "7 y default / 10 y
// configurable" means configurable UP: a deployment that could set 1 year would
// place itself below the regulatory minimum through a config file, which is the
// failure this gate exists to make impossible.
func TestFloorIsConfigurableUpwardOnly(t *testing.T) {
	t.Run("above the floor is accepted", func(t *testing.T) {
		p, err := NewPolicy(Config{Floor: TenYearFloor})
		if err != nil {
			t.Fatalf("NewPolicy(10y): %v", err)
		}
		if p.Floor() != TenYearFloor {
			t.Errorf("floor = %v, want %v", p.Floor(), TenYearFloor)
		}
	})

	t.Run("below the floor is refused", func(t *testing.T) {
		_, err := NewPolicy(Config{Floor: DefaultFloor - time.Hour})
		if !errors.Is(err, ErrBelowFloor) {
			t.Errorf("NewPolicy(floor - 1h) error = %v, want ErrBelowFloor; a config "+
				"file could otherwise put the deployment under the regulatory minimum", err)
		}
	})
}

// TestPrematureDeletionIsRefused is the keystone. This is what a DORA / NYDFS
// reviewer tests: attempt an early removal through the product's own surface and
// require it to be refused.
func TestPrematureDeletionIsRefused(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	// A record written one day inside the floor.
	written := now.Add(-DefaultFloor).Add(24 * time.Hour)
	if err := p.MayDelete(written, now); !errors.Is(err, ErrWithinFloor) {
		t.Errorf("deleting a record one day inside the floor = %v, want ErrWithinFloor", err)
	}

	// One day outside it: permitted. Without this arm the guard could refuse
	// everything and still pass the case above.
	expired := now.Add(-DefaultFloor).Add(-24 * time.Hour)
	if err := p.MayDelete(expired, now); err != nil {
		t.Errorf("deleting a record one day past the floor = %v, want nil", err)
	}
}

// TestFloorBoundaryIsInclusive pins the edge. A record exactly at the floor has
// been retained for the full period, so removing it is permitted; an
// off-by-one here is the difference between meeting the regulation and missing
// it by a day, in whichever direction.
func TestFloorBoundaryIsInclusive(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)
	exactly := now.Add(-DefaultFloor)

	if err := p.MayDelete(exactly, now); err != nil {
		t.Errorf("a record retained for EXACTLY the floor was refused (%v); it has "+
			"served the full period", err)
	}
	if err := p.MayDelete(exactly.Add(time.Nanosecond), now); !errors.Is(err, ErrWithinFloor) {
		t.Errorf("a record one nanosecond short of the floor was permitted (%v)", err)
	}
}

// TestFutureWriteTimeIsRefused fails closed on a clock anomaly.
//
// The refusal alone does not bind the guard: a future write time yields a
// negative age, which is below the floor, so the floor check refuses it anyway.
// Mutation testing showed that deleting the explicit check leaves this green.
// TestFutureWriteTimeIsNamedAsSuch below binds what only this guard gives.
func TestFutureWriteTimeIsRefused(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	if err := p.MayDelete(now.Add(time.Hour), now); err == nil {
		t.Error("a record written in the FUTURE was cleared for deletion; a clock " +
			"setback would then authorise removing records that are not old enough")
	}
}

// TestFutureWriteTimeIsNamedAsSuch separates a clock anomaly from an ordinary
// too-young record. Both are refused, but they are different incidents: "still
// within the floor" is the system working, and an operator seeing it moves on;
// a future timestamp means the clock or the metadata is wrong, and every other
// retention decision made against that clock is suspect.
//
// Reporting the anomaly as a routine floor refusal hides a fault that affects
// far more than the one record.
func TestFutureWriteTimeIsNamedAsSuch(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	future := p.MayDelete(now.Add(time.Hour), now)
	if future == nil {
		t.Fatal("a future-stamped record was cleared for deletion")
	}
	if !errors.Is(future, ErrWriteTimeInFuture) {
		t.Errorf("a future write time is reported as %v, not as a clock anomaly; the "+
			"check is being shadowed by the floor comparison and a wrong clock reads "+
			"as a routine refusal", future)
	}

	// The control: an ordinary too-young record must NOT be reported as a clock
	// anomaly, or the new assertion could be satisfied by naming everything one.
	young := p.MayDelete(now.Add(-time.Hour), now)
	if errors.Is(young, ErrWriteTimeInFuture) {
		t.Errorf("an ordinary too-young record is reported as a clock anomaly (%v)", young)
	}
	if !errors.Is(young, ErrWithinFloor) {
		t.Errorf("an ordinary too-young record is reported as %v, want ErrWithinFloor", young)
	}
}

// TestZeroWriteTimeIsRefused is separate from the future case because it fails
// for a different reason: a zero time is missing metadata, not a clock anomaly,
// and it arithmetically looks ancient. A build that only guarded the future
// would happily delete every record whose timestamp failed to load.
func TestZeroWriteTimeIsRefused(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	if err := p.MayDelete(time.Time{}, now); !errors.Is(err, ErrUnknownWriteTime) {
		t.Errorf("a record with NO write time was cleared for deletion (%v); missing "+
			"metadata reads as arbitrarily old, so the floor would not apply to it", err)
	}
}

// TestHotWindowIsNinetyDays pins the tier boundary NFR-COMP-01 names. It is
// distinct from the floor: the hot window says when a segment ROTATES, the floor
// says when a record may be removed, and confusing the two would rotate on a
// 7-year cadence or delete after 90 days.
func TestHotWindowIsNinetyDays(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	if days := p.HotWindow().Hours() / 24; days != 90 {
		t.Errorf("hot window = %.0f days, want 90", days)
	}
	if p.HotWindow() >= p.Floor() {
		t.Error("the hot window is not shorter than the retention floor; the tiers " +
			"would collapse into one")
	}
}

// TestRotationIsNotDeletion keeps the two verbs apart. Moving a sealed segment
// to the cold tier happens INSIDE the floor by design — that is the whole point
// of a hot tier — so a gate that treated a tier move as a deletion would make
// rotation impossible for seven years.
func TestRotationIsNotDeletion(t *testing.T) {
	p, err := NewPolicy(Config{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	now := time.Date(2033, 6, 1, 0, 0, 0, 0, time.UTC)

	// A segment older than the hot window but far inside the retention floor.
	sealed := now.Add(-100 * 24 * time.Hour)

	if !p.ShouldRotate(sealed, now) {
		t.Error("a segment older than the 90-day hot window was not due for rotation")
	}
	if err := p.MayDelete(sealed, now); !errors.Is(err, ErrWithinFloor) {
		t.Errorf("the same segment was cleared for DELETION (%v); rotation and "+
			"deletion are different verbs and only one of them is due", err)
	}

	// Inside the hot window: not due.
	fresh := now.Add(-24 * time.Hour)
	if p.ShouldRotate(fresh, now) {
		t.Error("a one-day-old segment was due for rotation; the hot tier would be empty")
	}
}

// TestHotWindowIsConfigurableWithinTheFloor allows a deployment to shorten the
// hot tier (smaller boot-time validation, earlier cold commit) but never to push
// it past the floor, which would leave records due for rotation after they were
// already due for deletion.
func TestHotWindowIsConfigurableWithinTheFloor(t *testing.T) {
	if _, err := NewPolicy(Config{HotWindow: 7 * 24 * time.Hour}); err != nil {
		t.Errorf("a 7-day hot window was refused: %v", err)
	}
	if _, err := NewPolicy(Config{HotWindow: DefaultFloor + time.Hour}); !errors.Is(err, ErrHotWindowTooLong) {
		t.Errorf("a hot window longer than the floor was accepted; a segment would " +
			"become deletable before it was ever rotated")
	}
	if _, err := NewPolicy(Config{HotWindow: -time.Hour}); err == nil {
		t.Error("a negative hot window was accepted")
	}
}
