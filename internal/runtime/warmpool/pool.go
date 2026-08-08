// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package warmpool is a substrate-neutral create-ahead pool of pre-materialized,
// never-run sandbox units, keyed by their create-time profile. It pre-warms the
// expensive substrate-generic work (image pull, network create, container
// create) OFF the session-create path so a warm-hit create only writes the
// tenant handoff, renames, and starts the guest (NFR-PERF-02).
//
// It honors the pool NFRs by construction: a unit is provisioned under a
// non-tenant placeholder identity carrying zero tenant data (NFR-SEC-70); a
// claimed unit is specialized to a fresh host-attested identity BEFORE its first
// boot, so the guest binds the real identity at start (NFR-SEC-69); a unit that
// has run any session is destroyed and never returned (NFR-SEC-68 — this pool
// only ever hands out never-run units, so recycling a run guest is structurally
// impossible). Replenishment is watermark-by-bounded-channel: a background
// producer fills each per-profile ready channel to capacity and blocks, so
// consumption drives production with no timer.
package warmpool

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned by Claim and Get once the pool is shutting down.
var ErrClosed = errors.New("warmpool: closed")

// Unit is one pre-materialized, never-started sandbox the pool holds. It carries
// only the placeholder substrate identity (NFR-SEC-70): the provider-assigned id
// of the created-but-not-started container and the profile it was built under.
// It holds NO tenant data — the tenant handoff is written only at claim, into
// the live unit, before its first boot.
type Unit struct {
	// PlaceholderID is the substrate handle for the created-not-started unit
	// (the docker container id / name under the placeholder name). Claim renames
	// and starts it; the reaper destroys an unclaimed one.
	PlaceholderID string
	// Profile is the create-time key the unit was built under; a claim is only
	// served a unit from its own profile (image + resources + FUSE posture are
	// baked at create and cannot change at claim).
	Profile Profile
	// Handoff is an OPAQUE handle the Factory round-trips: the substrate-specific
	// placeholder handoff state (the docker Factory stores its handoff.Staged
	// here) so Destroy can reclaim it and a claim can specialize it. The pool
	// never inspects it — keeping the pool package free of any substrate import.
	Handoff any
}

// Profile is the create-time key a pooled unit is bound to. Two sessions share a
// pooled unit only if their Profile matches exactly, because the image digest,
// resource caps, and FUSE posture are all baked at container create and a claim
// can change none of them.
type Profile struct {
	// ImageRef is the sandbox image the unit was created from.
	ImageRef string
	// CPUCores / MemoryBytes / PidsLimit are the hard caps baked at create.
	CPUCores    float64
	MemoryBytes int64
	PidsLimit   int64
	// FUSE is the storage-mount posture baked at create (the runtime/cap/device
	// gate): a pure-exec unit and a storage unit are not interchangeable.
	FUSE bool
}

// Factory creates and destroys placeholder units for one substrate. It is the
// pool's only door to the provider; a test injects a fake. Create must NOT start
// the unit (a pooled unit is never-run); Destroy reclaims an unclaimed unit.
type Factory interface {
	// CreatePlaceholder materializes a never-started unit under a non-tenant
	// placeholder identity for the given profile (NFR-SEC-70). It returns the
	// substrate handle the pool later hands to a claim or the reaper.
	CreatePlaceholder(ctx context.Context, p Profile) (Unit, error)
	// DestroyPlaceholder reclaims an unclaimed unit (the reaper / shutdown path).
	DestroyPlaceholder(ctx context.Context, u Unit) error
}

// Pool is a set of per-profile bounded ready channels plus one background
// producer per profile. It is safe for concurrent Claim/Get.
type Pool struct {
	factory  Factory
	capacity int

	mu     sync.Mutex
	ready  map[Profile]chan Unit
	closed bool
	wg     sync.WaitGroup
	// cancelFill cancels every producer on Close.
	cancelFill context.CancelFunc
	fillCtx    context.Context
}

// New builds a pool with the given per-profile ready-channel capacity (the
// watermark: the producer fills to capacity then blocks). capacity <= 0 disables
// warming (every Get returns a miss), which is the minimal-shelf default — no
// pool, cold creates only.
func New(factory Factory, capacity int) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		factory:    factory,
		capacity:   capacity,
		ready:      map[Profile]chan Unit{},
		cancelFill: cancel,
		fillCtx:    ctx,
	}
}

// Warm ensures a background producer is running for the given profile, filling
// its ready channel to capacity. It is idempotent: calling it again for a
// profile already warming is a no-op. A deployment calls it once per profile it
// wants pre-warmed. With capacity <= 0 it is a no-op (warming disabled).
func (p *Pool) Warm(profile Profile) {
	if p.capacity <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if _, ok := p.ready[profile]; ok {
		return // already warming this profile
	}
	ch := make(chan Unit, p.capacity)
	p.ready[profile] = ch
	p.wg.Add(1)
	go p.fill(profile, ch)
}

// fill is the watermark producer for one profile: it creates one unit at a time
// and blocks sending it into the bounded channel, so the channel capacity is the
// watermark and consumption pulls production. A create error is logged-and-
// retried by continuing the loop (the pool degrades to empty and Get returns a
// miss rather than the producer dying) — bounded by the context cancel on Close.
func (p *Pool) fill(profile Profile, ch chan Unit) {
	defer p.wg.Done()
	for {
		if p.fillCtx.Err() != nil {
			return
		}
		u, err := p.factory.CreatePlaceholder(p.fillCtx, profile)
		if err != nil {
			// Degrade to empty rather than die: on the next iteration the context
			// check short-circuits if we are closing, else we retry a create.
			if p.fillCtx.Err() != nil {
				return
			}
			continue
		}
		select {
		case ch <- u:
		case <-p.fillCtx.Done():
			// Closing while holding a freshly created unit: destroy it so it does
			// not leak (it never entered the channel, so Close's drain won't see it).
			_ = p.factory.DestroyPlaceholder(context.WithoutCancel(p.fillCtx), u)
			return
		}
	}
}

// Get returns a warm unit for the profile without blocking, or (Unit{}, false)
// if none is ready (a pool MISS — the caller does a cold create). It never
// waits: a warm-hit is only a warm-hit if a unit is already sitting in the
// channel, so a miss falls straight through to the cold path rather than paying
// a create latency inside the "warm" path.
func (p *Pool) Get(profile Profile) (Unit, bool) {
	p.mu.Lock()
	ch, ok := p.ready[profile]
	closed := p.closed
	p.mu.Unlock()
	if closed || !ok {
		return Unit{}, false
	}
	select {
	case u := <-ch:
		return u, true
	default:
		return Unit{}, false
	}
}

// Close stops every producer and destroys every unit still sitting in a ready
// channel (unclaimed placeholders must not leak). It blocks until all producers
// have exited. After Close, Get always returns a miss.
func (p *Pool) Close(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	chans := make([]chan Unit, 0, len(p.ready))
	for _, ch := range p.ready {
		chans = append(chans, ch)
	}
	p.mu.Unlock()

	p.cancelFill() // signal every producer to exit
	p.wg.Wait()    // wait for them so no producer races the drain below

	var errs []error
	for _, ch := range chans {
		for {
			select {
			case u := <-ch:
				if err := p.factory.DestroyPlaceholder(ctx, u); err != nil {
					errs = append(errs, err)
				}
			default:
				goto next
			}
		}
	next:
	}
	return errors.Join(errs...)
}
