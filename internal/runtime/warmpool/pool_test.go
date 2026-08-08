// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package warmpool

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFactory is a recording Factory: it counts creates and destroys, hands out
// uniquely-numbered placeholder units, and can be scripted to fail creates. It
// asserts the never-run invariant structurally — it has NO Start method, so the
// pool physically cannot start a unit.
type fakeFactory struct {
	mu        sync.Mutex
	created   int64
	destroyed int64
	live      map[string]bool // placeholder ids currently alive (created, not destroyed)
	failNext  atomic.Bool
	seq       atomic.Int64
}

func newFakeFactory() *fakeFactory {
	return &fakeFactory{live: map[string]bool{}}
}

func (f *fakeFactory) CreatePlaceholder(_ context.Context, p Profile) (Unit, error) {
	if f.failNext.Swap(false) {
		return Unit{}, errors.New("create refused")
	}
	id := "ph-" + itoa(f.seq.Add(1))
	f.mu.Lock()
	f.created++
	f.live[id] = true
	f.mu.Unlock()
	return Unit{PlaceholderID: id, Profile: p}, nil
}

func (f *fakeFactory) DestroyPlaceholder(_ context.Context, u Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.destroyed++
	delete(f.live, u.PlaceholderID)
	return nil
}

func (f *fakeFactory) liveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var testProfile = Profile{ImageRef: "img@sha256:abc", CPUCores: 2, MemoryBytes: 512 << 20, PidsLimit: 256, FUSE: false}

// waitFor polls cond until true or the deadline, so a test never sleeps a fixed
// duration waiting on the background producer.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// TestGet_ReturnsAWarmHitAfterFill is the keystone: once a profile is warmed,
// Get returns a ready unit (a hit) without creating one on the Get path.
func TestGet_ReturnsAWarmHitAfterFill(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 3)
	defer p.Close(context.Background())
	p.Warm(testProfile)

	// The producer fills the channel to capacity in the background.
	waitFor(t, func() bool { return f.liveCount() >= 3 }) // 3 buffered + 1 in-flight = steady state

	u, ok := p.Get(testProfile)
	if !ok {
		t.Fatal("Get returned a miss on a warmed profile")
	}
	if u.Profile != testProfile {
		t.Errorf("claimed unit profile = %v, want the requested profile", u.Profile)
	}
	if u.PlaceholderID == "" {
		t.Error("claimed unit has no placeholder id")
	}
}

// TestGet_MissWhenProfileNotWarmed pins that an un-warmed profile is a straight
// miss (no blocking, no create) — the caller falls through to a cold create.
func TestGet_MissWhenProfileNotWarmed(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 3)
	defer p.Close(context.Background())
	// Warm ONLY testProfile; ask for a different one.
	p.Warm(testProfile)
	other := testProfile
	other.ImageRef = "other@sha256:def"

	if _, ok := p.Get(other); ok {
		t.Fatal("Get returned a hit for an un-warmed profile")
	}
}

// TestGet_MissWhenEmpty pins that a warmed-but-drained profile is a miss, not a
// block: Get never waits inside the warm path.
func TestGet_MissWhenEmpty(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 1)
	defer p.Close(context.Background())
	p.Warm(testProfile)
	waitFor(t, func() bool { return f.liveCount() >= 1 })

	if _, ok := p.Get(testProfile); !ok {
		t.Fatal("first Get should hit")
	}
	// The producer refills asynchronously; but if we drain faster than it fills,
	// a Get must MISS rather than block. Drain until a miss without deadlocking.
	done := make(chan struct{})
	go func() {
		for {
			if _, ok := p.Get(testProfile); !ok {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Get blocked on an empty channel instead of missing")
	}
}

// TestClose_DestroysUnclaimedUnitsNoLeak is the no-leak keystone: after Close,
// every placeholder the producer created is either claimed or destroyed — none
// leaks. A leaked never-run guest is a resource and a security liability
// (NFR-SEC-70 units carry a placeholder identity that must not linger).
func TestClose_DestroysUnclaimedUnitsNoLeak(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 4)
	p.Warm(testProfile)
	waitFor(t, func() bool { return f.liveCount() >= 4 })

	// Claim exactly one; it becomes the caller's responsibility, not the pool's.
	if _, ok := p.Get(testProfile); !ok {
		t.Fatal("expected a hit")
	}

	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The invariant, timing-independent: every unit the factory ever CREATED is
	// accounted for as either destroyed-by-the-pool or claimed-by-the-caller.
	// Nothing the pool retained leaks. (Asserting a bare live count would race the
	// producer's in-flight unit; this binds creation to disposition exactly.)
	f.mu.Lock()
	created, destroyed := f.created, f.destroyed
	f.mu.Unlock()
	const claimed = 1
	if destroyed != created-claimed {
		t.Errorf("leak: created=%d destroyed=%d claimed=%d — the pool retained %d unit(s) it neither destroyed nor handed out",
			created, destroyed, claimed, created-claimed-destroyed)
	}
	// And exactly the claimed unit remains live.
	if got := f.liveCount(); got != claimed {
		t.Errorf("after Close, %d placeholders live; want %d (only the claimed unit)", got, claimed)
	}
}

// TestFill_DegradesToEmptyOnCreateError pins that a create failure does NOT kill
// the producer: the pool degrades to empty (Get misses) and recovers on the next
// successful create rather than the producer dying on a transient.
func TestFill_DegradesToEmptyOnCreateError(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 2)
	defer p.Close(context.Background())
	f.failNext.Store(true) // the first create fails
	p.Warm(testProfile)

	// Despite the first failure, the producer keeps going and fills the channel.
	waitFor(t, func() bool { return f.liveCount() >= 2 })
	if _, ok := p.Get(testProfile); !ok {
		t.Fatal("pool did not recover after a transient create failure")
	}
}

// TestZeroCapacity_DisablesWarming pins the minimal-shelf default: capacity <= 0
// warms nothing, every Get misses, and no placeholder is ever created.
func TestZeroCapacity_DisablesWarming(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 0)
	defer p.Close(context.Background())
	p.Warm(testProfile)

	// Give any (erroneously-spawned) producer a chance to create.
	time.Sleep(50 * time.Millisecond)
	if f.liveCount() != 0 {
		t.Errorf("capacity 0 created %d placeholders; want 0 (warming disabled)", f.liveCount())
	}
	if _, ok := p.Get(testProfile); ok {
		t.Error("capacity 0 returned a hit; want a miss (no pool)")
	}
}

// TestWarm_IsIdempotent pins that warming a profile twice spawns ONE producer,
// not two racing producers overfilling / double-counting.
func TestWarm_IsIdempotent(t *testing.T) {
	f := newFakeFactory()
	p := New(f, 2)
	defer p.Close(context.Background())
	p.Warm(testProfile)
	p.Warm(testProfile) // second call must be a no-op
	waitFor(t, func() bool { return f.liveCount() >= 2 })

	// The channel capacity is 2; a single producer fills to 2 and blocks. Two
	// producers would still be bounded by the channel, but the live count would
	// briefly exceed 2 (each holding a just-created unit trying to send). Assert
	// it never exceeds capacity+1 over a short window (one in-flight send max).
	for i := 0; i < 50; i++ {
		if f.liveCount() > 3 {
			t.Fatalf("live count %d exceeds one producer's bound; a second producer is running", f.liveCount())
		}
		time.Sleep(2 * time.Millisecond)
	}
}
