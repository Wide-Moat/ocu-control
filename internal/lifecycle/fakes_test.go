// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/mountcfg"
	"github.com/Wide-Moat/ocu-control/internal/provisioning"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// newTestSigner loads a real cred.Signer over a freshly generated Ed25519 key on a
// FakeClock, attaches the shared Revoker, and returns both so a test can assert the
// create-path mint recorded a jti the teardown revoke later marks dead.
func newTestSigner(t *testing.T, clk state.Clock) (*cred.Signer, *cred.Revoker) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
	signer, err := cred.LoadSignerFromMount(path, clk, cred.Config{
		Alg:             cred.AlgEdDSA,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		ExecIssuer:      "https://control.example/exec-provisional",
		ExecAudience:    "guest.exec.provisional",
		StorageTTL:      15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("LoadSignerFromMount: %v", err)
	}
	revoker := cred.NewRevoker(clk)
	signer.UseRevoker(revoker)
	return signer, revoker
}

// testMountDefaults builds a valid MountDefaults through the validating
// constructors so Render accepts it.
func testMountDefaults(t *testing.T) mountcfg.MountDefaults {
	t.Helper()
	mode, err := mountcfg.NewVfsCacheMode("writes")
	if err != nil {
		t.Fatalf("NewVfsCacheMode: %v", err)
	}
	size, err := mountcfg.NewByteSize("256M")
	if err != nil {
		t.Fatalf("NewByteSize: %v", err)
	}
	dir, err := mountcfg.NewOctal("0700")
	if err != nil {
		t.Fatalf("NewOctal(dir): %v", err)
	}
	file, err := mountcfg.NewOctal("0600")
	if err != nil {
		t.Fatalf("NewOctal(file): %v", err)
	}
	return mountcfg.MountDefaults{VfsCacheMode: mode, VfsCacheMaxSize: size, DirPerms: dir, FilePerms: file}
}

// testServiceURL and testCACert are valid against the frozen top-level patterns
// (^https:// and the BEGIN CERTIFICATE marker) so Render does not refuse them.
const (
	testServiceURL = "https://filestore.example/v1"
	testCACert     = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
)

// recordingPusher wraps the real filesystem Pusher so the happy path lands a config
// on the host-owned bind (the no-orphan test asserts the on-disk file is gone after
// an unwind), while letting a test arm a FAIL on Push to drive the render/push
// stage fault. It records the surface for the compensator assertion and tracks the
// last pushed path so a residue check can confirm Scrub removed it.
type recordingPusher struct {
	inner provisioning.Pusher
	mu    sync.Mutex

	pushCalls  int
	scrubCalls int
	failPush   bool
	lastPath   string
}

func newRecordingPusher() *recordingPusher {
	return &recordingPusher{inner: provisioning.NewPusher()}
}

func (p *recordingPusher) Push(ctx context.Context, staged handoff.Staged, cfgBytes []byte) (provisioning.Pushed, error) {
	p.mu.Lock()
	p.pushCalls++
	fail := p.failPush
	p.mu.Unlock()
	if fail {
		return provisioning.Pushed{}, errPushInjected
	}
	pushed, err := p.inner.Push(ctx, staged, cfgBytes)
	if err == nil {
		p.mu.Lock()
		p.lastPath = pushed.Path
		p.mu.Unlock()
	}
	return pushed, err
}

func (p *recordingPusher) Scrub(ctx context.Context, pushed provisioning.Pushed) error {
	p.mu.Lock()
	p.scrubCalls++
	p.mu.Unlock()
	return p.inner.Scrub(ctx, pushed)
}

func (p *recordingPusher) counts() (push, scrub int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pushCalls, p.scrubCalls
}

// pushedPath returns the host-side path the last successful Push landed at, so a
// residue assertion can confirm the config file is gone after an unwind.
func (p *recordingPusher) pushedPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPath
}

// errPushInjected is the typed fault recordingPusher returns when armed, so the
// no-orphan test can attribute the render/push-stage failure to the injected fault.
var errPushInjected = errors.New("fakes: injected push fault")

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

// gracefulStops returns how many GracefulStop calls the finalizer has made, so an
// ordering assertion can read whether the authoritative teardown ran at a given
// point relative to the advisory control-RPC dial.
func (p *recordingProvider) gracefulStops() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gracefulStopCalls
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

// SockDir delegates to the wrapped real Stager so the advisory control-RPC dial on
// Destroy re-derives the SAME per-session sock path the create path staged.
func (s *faultStager) SockDir(name runtime.SessionName) string {
	return s.inner.SockDir(name)
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
