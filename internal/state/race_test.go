// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// The tests below are written to run under the race detector (go test -race).
// Each exercises a contention path the Store's locking exists to make safe and
// asserts the outcome is exactly-once where the contract requires it, with no
// data race and no double-book, double-credit, or orphan.

// raceOwner is the host-derived identity the race tests reserve under.
var raceOwner = Identity{Tenant: "tenant-r", Caller: "caller-r"}

// TestRace_ConcurrentSameKey fires N goroutines at Reserve for the same key.
// Exactly one must win; the other N-1 must see ErrReservationExists, and the
// store must hold exactly one live row.
func TestRace_ConcurrentSameKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewInMemory(NewFakeClock(conformanceStart))

	const goroutines = 64
	const key = "contended"

	var wins, exists, other int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Reserve(ctx, key, raceOwner)
			switch {
			case err == nil:
				atomic.AddInt64(&wins, 1)
			case errors.Is(err, ErrReservationExists):
				atomic.AddInt64(&exists, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if other != 0 {
		t.Fatalf("unexpected non-conflict errors: %d", other)
	}
	if wins != 1 {
		t.Fatalf("exactly one Reserve must win: got %d winners", wins)
	}
	if exists != goroutines-1 {
		t.Fatalf("the rest must see ErrReservationExists: want %d, got %d", goroutines-1, exists)
	}

	row, err := s.LookupSession(ctx, key)
	if err != nil {
		t.Fatalf("LookupSession: unexpected error %v", err)
	}
	if row.State != StateReserved {
		t.Fatalf("the one live row must be RESERVED, got %v", row.State)
	}
}

// TestRace_ConcurrentDistinctKeys reserves many distinct keys in parallel. All
// must succeed: distinct keys hash onto independent stripes, so there is real
// parallelism and no false contention.
func TestRace_ConcurrentDistinctKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewInMemory(NewFakeClock(conformanceStart))

	const goroutines = 128

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(idx int) {
			defer wg.Done()
			key := "key-" + itoa(idx)
			_, errs[idx] = s.Reserve(ctx, key, raceOwner)
		}(g)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("distinct-key Reserve %d: unexpected error %v", i, err)
		}
	}
	// Every distinct key holds a live row.
	for i := 0; i < goroutines; i++ {
		row, err := s.LookupSession(ctx, "key-"+itoa(i))
		if err != nil {
			t.Fatalf("LookupSession key-%d: unexpected error %v", i, err)
		}
		if row.State != StateReserved {
			t.Fatalf("key-%d: want RESERVED, got %v", i, row.State)
		}
	}
}

// TestRace_ReserveVsDeny engages the kill-switch and then hammers Reserve from
// many goroutines. No Reserve may succeed while the switch is observably
// engaged: a concurrent SetDeny-before-Reserve must never leave a committed row
// behind. Here the switch is set before the storm, so every Reserve must be
// refused with the kill-switch error and no row may exist for any key.
func TestRace_ReserveVsDeny(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewInMemory(NewFakeClock(conformanceStart))

	if err := s.SetDeny(ctx, DenyEntry{Scope: ScopeGlobal}); err != nil {
		t.Fatalf("SetDeny global: unexpected error %v", err)
	}

	const goroutines = 64
	var refused, leaked int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			key := "k-" + itoa(idx%8)
			_, err := s.Reserve(ctx, key, raceOwner)
			if errors.Is(err, ErrKillSwitchEngaged) {
				atomic.AddInt64(&refused, 1)
			} else if err == nil {
				atomic.AddInt64(&leaked, 1)
			}
		}(g)
	}
	close(start)
	wg.Wait()

	if leaked != 0 {
		t.Fatalf("a committed row leaked under an engaged kill-switch: %d", leaked)
	}
	if refused != goroutines {
		t.Fatalf("every Reserve must be refused by the kill-switch: want %d, got %d", goroutines, refused)
	}
	// No key may hold a row.
	for i := 0; i < 8; i++ {
		if _, err := s.LookupSession(ctx, "k-"+itoa(i)); !errors.Is(err, ErrReservationNotFound) {
			t.Fatalf("kill-switch refusal left a row for k-%d: %v", i, err)
		}
	}
}

// TestRace_ChargeStorm fires K concurrent +1 charges at one cell with a limit of
// K/2. Exactly K/2 must succeed and the rest must see ErrQuotaExceeded; the
// final counter must read exactly K/2, proving the atomic check-and-increment
// admits no overcommit under contention.
func TestRace_ChargeStorm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewInMemory(NewFakeClock(conformanceStart))

	const k = 64
	const limit = k / 2
	key := QuotaKey{Dim: DimConcurrentSessions, Identity: raceOwner}

	var ok, exceeded, other int64
	var wg sync.WaitGroup
	wg.Add(k)
	start := make(chan struct{})
	for i := 0; i < k; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Charge(ctx, key, 1, limit)
			switch {
			case err == nil:
				atomic.AddInt64(&ok, 1)
			case errors.Is(err, ErrQuotaExceeded):
				atomic.AddInt64(&exceeded, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if other != 0 {
		t.Fatalf("unexpected non-quota errors: %d", other)
	}
	if ok != limit {
		t.Fatalf("exactly limit charges must succeed: want %d, got %d", limit, ok)
	}
	if exceeded != k-limit {
		t.Fatalf("the rest must be refused: want %d, got %d", k-limit, exceeded)
	}

	final, err := s.ReadQuota(ctx, key)
	if err != nil {
		t.Fatalf("ReadQuota: unexpected error %v", err)
	}
	if final != limit {
		t.Fatalf("final counter must equal the limit: want %d, got %d", limit, final)
	}
}

// TestRace_CommitReleaseRace races a Commit against a Release on one RESERVED
// row from two goroutines. Exactly one wins the RESERVED row; the loser sees a
// typed conflict (Commit of a released row, or Release found nothing live to
// race differently). The terminal row is consistent either way.
func TestRace_CommitReleaseRace(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Run many trials so the scheduler interleaves the two mutators both ways.
	const trials = 200
	for trial := 0; trial < trials; trial++ {
		s := NewInMemory(NewFakeClock(conformanceStart))
		const key = "k"
		if _, err := s.Reserve(ctx, key, raceOwner); err != nil {
			t.Fatalf("trial %d: Reserve: unexpected error %v", trial, err)
		}

		var commitErr, releaseErr error
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() {
			defer wg.Done()
			<-start
			_, commitErr = s.Commit(ctx, key, raceOwner)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, releaseErr = s.Release(ctx, key, raceOwner)
		}()
		close(start)
		wg.Wait()

		// Release never errors here (it owns the row and the key exists). Whether
		// Commit ran before or after Release decides Commit's outcome:
		//   - Commit before Release: Commit succeeds (RESERVED→ACTIVE), then
		//     Release succeeds (ACTIVE→RELEASED). Final state RELEASED.
		//   - Release before Commit: Release succeeds (RESERVED→RELEASED), then
		//     Commit sees a released row and returns ErrReservationConflict.
		// Either ordering ends with exactly one of these shapes; both leave the
		// row in a single consistent terminal state.
		if releaseErr != nil {
			t.Fatalf("trial %d: Release must not error: %v", trial, releaseErr)
		}
		if commitErr != nil && !errors.Is(commitErr, ErrReservationConflict) {
			t.Fatalf("trial %d: Commit error must be a conflict or nil, got %v", trial, commitErr)
		}

		row, err := s.LookupSession(ctx, key)
		if err != nil {
			t.Fatalf("trial %d: LookupSession: unexpected error %v", trial, err)
		}
		if commitErr == nil {
			// Commit won the RESERVED row first, then Release tombstoned it.
			if row.State != StateReleased {
				t.Fatalf("trial %d: commit-then-release must end RELEASED, got %v", trial, row.State)
			}
		} else {
			// Release won first; Commit was rejected against the tombstone.
			if row.State != StateReleased {
				t.Fatalf("trial %d: release-first must end RELEASED, got %v", trial, row.State)
			}
		}
	}
}

// itoa renders a small non-negative int without pulling in strconv at every call
// site; it is plenty for the bounded indices these race tests generate.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
