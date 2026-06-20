// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// recordingProvider is the in-test RuntimeProvider that records every Materialize,
// ForceKill, GracefulStop, and Reconcile so a no-orphan assertion can prove the
// substrate holds nothing after an unwind. It can be armed to FAIL Materialize (to
// drive the S6 fault) and tracks the set of live RuntimeIDs so a test can assert
// every materialized container was later force-killed.
type recordingProvider struct {
	mu sync.Mutex

	// live is the set of RuntimeIDs Materialize created and a finalizer verb has not
	// yet removed. A non-empty live set after an unwind is an orphan.
	live map[string]bool
	// materializeCalls, forceKillCalls, gracefulStopCalls, reconcileCalls count the
	// surface so a per-stage compensator assertion can read them.
	materializeCalls  int
	forceKillCalls    int
	gracefulStopCalls int
	reconcileCalls    int

	// failMaterialize, when true, makes Materialize return ErrMaterialize having
	// created nothing (modelling the provider's own internal rollback).
	failMaterialize bool
	// nextRuntimeID seeds a unique RuntimeID per Materialize.
	nextRuntimeID int
	// reconcileOrphans is the slice Reconcile returns (substrate orphans to sweep).
	reconcileOrphans []runtime.Sandbox
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{live: make(map[string]bool)}
}

func (p *recordingProvider) Materialize(ctx context.Context, spec runtime.SessionSpec) (runtime.Sandbox, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.materializeCalls++
	if err := ctx.Err(); err != nil {
		return runtime.Sandbox{}, fmt.Errorf("%w: %w", runtime.ErrMaterialize, err)
	}
	if p.failMaterialize {
		// The provider rolled back its own partial create: nothing survives below the
		// seam, so no live id is recorded.
		return runtime.Sandbox{}, runtime.ErrMaterialize
	}
	p.nextRuntimeID++
	id := fmt.Sprintf("ctr-%d", p.nextRuntimeID)
	p.live[id] = true
	return runtime.Sandbox{
		Name:      spec.Name,
		RuntimeID: id,
	}, nil
}

func (p *recordingProvider) Teardown() runtime.RuntimeTeardown {
	return recordingTeardown{p: p}
}

func (p *recordingProvider) Reconcile(ctx context.Context) ([]runtime.Sandbox, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reconcileCalls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]runtime.Sandbox, len(p.reconcileOrphans))
	copy(out, p.reconcileOrphans)
	return out, nil
}

// liveCount returns the number of containers the provider still holds.
func (p *recordingProvider) liveCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live)
}

// recordingTeardown is the finalizer handle the recordingProvider hands out. Each
// verb removes the sandbox's RuntimeID from the live set (idempotent) and counts the
// call.
type recordingTeardown struct{ p *recordingProvider }

func (t recordingTeardown) GracefulStop(ctx context.Context, sess runtime.Sandbox, _ runtime.Duration) error {
	t.p.mu.Lock()
	defer t.p.mu.Unlock()
	t.p.gracefulStopCalls++
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", runtime.ErrTeardown, err)
	}
	delete(t.p.live, sess.RuntimeID)
	return nil
}

func (t recordingTeardown) ForceKill(ctx context.Context, sess runtime.Sandbox) error {
	t.p.mu.Lock()
	defer t.p.mu.Unlock()
	t.p.forceKillCalls++
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", runtime.ErrTeardown, err)
	}
	delete(t.p.live, sess.RuntimeID)
	return nil
}

// faultStager wraps a real filesystem handoff.Stager so the happy path stages and
// unstages real temp-dir trees (the no-orphan test asserts the on-disk root is gone),
// while letting a test arm a FAIL on Stage to drive the S5 fault without touching the
// filesystem. It counts the surface for the compensator assertion.
type faultStager struct {
	inner handoff.Stager
	mu    sync.Mutex

	stageCalls   int
	unstageCalls int
	// failStage, when true, makes Stage fail closed having staged nothing on disk.
	failStage bool
}

func newFaultStager(base string) *faultStager {
	return &faultStager{inner: handoff.NewStager(base)}
}

func (s *faultStager) Stage(ctx context.Context, name runtime.SessionName, pubKey []byte, mounts []runtime.MountIntent) (handoff.Staged, error) {
	s.mu.Lock()
	s.stageCalls++
	fail := s.failStage
	s.mu.Unlock()
	if fail {
		return handoff.Staged{}, errStageInjected
	}
	return s.inner.Stage(ctx, name, pubKey, mounts)
}

func (s *faultStager) Unstage(ctx context.Context, st handoff.Staged) error {
	s.mu.Lock()
	s.unstageCalls++
	s.mu.Unlock()
	return s.inner.Unstage(ctx, st)
}

func (s *faultStager) counts() (stage, unstage int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stageCalls, s.unstageCalls
}

// errStageInjected is the typed fault the faultStager returns when armed, so the
// no-orphan test can attribute an S5 failure to the injected fault.
var errStageInjected = errors.New("fakes: injected stage fault")

// listerStore wraps an in-memory Store and adds the LiveLister capability so the
// reconciler and the kill-switch can enumerate live rows. The in-memory Store
// exposes no list-all, so the wrapper records every key reserved through it and
// snapshots their current rows on LiveSessions, returning only the RESERVED+ACTIVE
// ones. It is safe for concurrent use.
type listerStore struct {
	state.Store
	mu   sync.Mutex
	keys map[string]bool
}

func newListerStore(inner state.Store) *listerStore {
	return &listerStore{Store: inner, keys: make(map[string]bool)}
}

func (s *listerStore) Reserve(ctx context.Context, key string, owner state.Identity) (state.SessionRow, error) {
	row, err := s.Store.Reserve(ctx, key, owner)
	if err == nil {
		s.mu.Lock()
		s.keys[key] = true
		s.mu.Unlock()
	}
	return row, err
}

func (s *listerStore) LiveSessions(ctx context.Context) ([]state.SessionRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	keys := make([]string, 0, len(s.keys))
	for k := range s.keys {
		keys = append(keys, k)
	}
	s.mu.Unlock()
	var out []state.SessionRow
	for _, k := range keys {
		row, err := s.Store.LookupSession(ctx, k)
		if err != nil {
			if errors.Is(err, state.ErrReservationNotFound) {
				continue
			}
			return nil, err
		}
		if row.State == state.StateReserved || row.State == state.StateActive {
			out = append(out, row)
		}
	}
	return out, nil
}
