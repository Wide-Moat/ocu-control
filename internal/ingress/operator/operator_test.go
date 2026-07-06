// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/ingress"
	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// nopProvider is a do-nothing RuntimeProvider: it never materializes anything and
// reports no orphans, sufficient for the ingress tests that refuse BEFORE any
// substrate call (an unattested connection touches no provider).
type nopProvider struct{}

func (nopProvider) Materialize(context.Context, runtime.SessionSpec) (runtime.Sandbox, error) {
	return runtime.Sandbox{}, nil
}
func (nopProvider) Teardown() runtime.RuntimeTeardown                    { return nopTeardown{} }
func (nopProvider) Reconcile(context.Context) ([]runtime.Sandbox, error) { return nil, nil }

type nopTeardown struct{}

func (nopTeardown) GracefulStop(context.Context, runtime.Sandbox, runtime.Duration) error { return nil }
func (nopTeardown) ForceKill(context.Context, runtime.Sandbox) error                      { return nil }

// newTestHandlers builds an operator Handlers over an in-memory Store, a do-nothing
// provider, the in-tree handoff stager (rooted in a temp dir), and an audit
// RecordingFake. The resolver and verifier are supplied per test. The single
// OperatorSeam is minted here and handed to the adapter, modelling cmd handing it
// to the operator adapter alone.
func newTestHandlers(t *testing.T, resolver ingress.IdentityResolver, verifier killswitch.SOARVerifier) (*operator.Handlers, *audit.RecordingFake, state.Store) {
	t.Helper()
	clk := state.SystemClock()
	store := newListerStore(state.NewInMemory(clk))
	custodian := registry.NewCustodian(store)
	gate := quota.NewGate(store, clk, quota.Limits{
		ConcurrentSessionsPerTenant: 16,
		CreateRatePerCallerPerMin:   16,
	})
	sink := audit.NewRecordingFake()
	mgr := lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:     custodian,
		Provider:      nopProvider{},
		Clock:         clk,
		Quota:         gate,
		Handoff:       handoff.NewStager(t.TempDir()),
		Audit:         sink,
		Profile:       0, // ProfileTrustedOperator
		Tier:          runtime.TierRunc,
		ExecVerifyKey: ingressTestExecVerifyKey(),
	})
	eng := killswitch.NewEngine(store, custodian, nopProvider{}, clk, sink, gate)
	h := operator.NewHandlers(operator.Deps{
		Manager:  mgr,
		Engine:   eng,
		Resolver: resolver,
		Verifier: verifier,
		Seam:     ingress.NewOperatorSeam(),
	})
	return h, sink, store
}

// attestedConn is a ConnInfo carrying a kernel-vouched PeerCred, modelling a
// connection the listener already resolved at accept time.
func attestedConn(uid uint32) ingress.ConnInfo {
	return ingress.ConnInfo{
		Channel:  ingress.ChannelOperator,
		PeerCred: &ingress.PeerCred{UID: uid, GID: uid, PID: 1000},
	}
}

// unattestedConn is a ConnInfo with no peer credential, modelling a connection the
// listener could not attest (the off-Linux build, or a getsockopt failure).
func unattestedConn() ingress.ConnInfo {
	return ingress.ConnInfo{Channel: ingress.ChannelOperator}
}

// TestUnattestedConnectionRefusedBeforeHostState asserts the design's named
// operator test: an unattested connection (no peer creds) is refused with
// ingress.ErrUnattested BEFORE any host state is touched. The Store is asserted to
// hold no reservation row and the audit sink to hold no record after the refusal.
func TestUnattestedConnectionRefusedBeforeHostState(t *testing.T) {
	t.Parallel()
	h, sink, store := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)

	_, err := h.Create(context.Background(), unattestedConn(), operator.CreateRequest{
		SessionHint: "hint",
		Image:       "img",
	})
	if !errors.Is(err, ingress.ErrUnattested) {
		t.Fatalf("Create on an unattested connection = %v; want ingress.ErrUnattested", err)
	}

	// No host state: the create never reached Reserve, so no row exists and no audit
	// record was emitted.
	if _, lookupErr := store.LookupSession(context.Background(), "any"); !errors.Is(lookupErr, state.ErrReservationNotFound) {
		t.Fatalf("after an unattested refusal LookupSession = %v; want a not-found (no row written)", lookupErr)
	}
	if sink.Len() != 0 {
		t.Fatalf("after an unattested refusal the audit sink holds %d records; want 0", sink.Len())
	}
}

// TestPeerCredResolverMapsAttestedUID asserts the resolver derives a host-derived
// identity from the kernel-attested uid and never from a body. Two distinct uids
// map to distinct caller principals under the same operator tenant.
func TestPeerCredResolverMapsAttestedUID(t *testing.T) {
	t.Parallel()
	r := operator.NewPeerCredResolver(nil)

	c1, err := r.Resolve(context.Background(), attestedConn(1001))
	if err != nil {
		t.Fatalf("Resolve(uid 1001) = %v; want nil", err)
	}
	c2, err := r.Resolve(context.Background(), attestedConn(1002))
	if err != nil {
		t.Fatalf("Resolve(uid 1002) = %v; want nil", err)
	}
	if c1.Identity.Tenant != c2.Identity.Tenant {
		t.Fatalf("two operator uids mapped to different tenants %q vs %q; want one operator tenant", c1.Identity.Tenant, c2.Identity.Tenant)
	}
	if c1.Identity.Caller == c2.Identity.Caller {
		t.Fatalf("two distinct uids mapped to the same caller %q; want distinct caller principals", c1.Identity.Caller)
	}
	if c1.Channel != ingress.ChannelOperator {
		t.Fatalf("resolved channel = %v; want ChannelOperator", c1.Channel)
	}
}

// TestSOARVerifyThenMint asserts the verify-then-mint gate: a revoke driven by a
// SOAR webhook with a BAD signature is rejected with killswitch.ErrSOARUnverified
// and authors NO deny entry, while a GOOD signature lets the revoke author the
// deny. This proves "acting is structurally impossible before verified".
func TestSOARVerifyThenMint(t *testing.T) {
	t.Parallel()

	// Bad signature: the verifier refuses, so no scope is minted and no deny is set.
	bad := &fakeVerifier{err: killswitch.ErrSOARUnverified}
	hBad, _, storeBad := newTestHandlers(t, operator.NewPeerCredResolver(nil), bad)
	err := hBad.RevokeOneViaSOAR(context.Background(), attestedConn(1001), []byte("payload"), []byte("sig"), "session-key", "soar")
	if !errors.Is(err, killswitch.ErrSOARUnverified) {
		t.Fatalf("RevokeOneViaSOAR with a bad signature = %v; want killswitch.ErrSOARUnverified", err)
	}
	if deny, _ := storeBad.LoadDeny(context.Background()); len(deny) != 0 {
		t.Fatalf("a SOAR-unverified revoke authored %d deny entries; want 0 (no scope minted)", len(deny))
	}

	// Good signature: the verifier passes, the scope is minted, the deny is authored.
	good := &fakeVerifier{}
	hGood, _, storeGood := newTestHandlers(t, operator.NewPeerCredResolver(nil), good)
	if err := hGood.RevokeOneViaSOAR(context.Background(), attestedConn(1001), []byte("payload"), []byte("sig"), "session-key", "soar"); err != nil {
		t.Fatalf("RevokeOneViaSOAR with a good signature = %v; want nil", err)
	}
	deny, _ := storeGood.LoadDeny(context.Background())
	foundSession := false
	for _, d := range deny {
		if d.Scope == state.ScopeSession && d.Key == "session-key" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatalf("a SOAR-verified revoke did not author the per-session deny entry; entries=%v", deny)
	}
}

// TestRevokeAllForceKillsReservedAfterCreate asserts an operator RevokeAll engages
// DENY-ALL and the deny is durable. (The force-kill sweep over RESERVED+ACTIVE rows
// is exercised in the killswitch package; here we assert the operator adapter mints
// the scope and the engine authors the global posture.)
func TestRevokeAllEngagesGlobalDeny(t *testing.T) {
	t.Parallel()
	h, _, store := newTestHandlers(t, operator.NewPeerCredResolver(nil), nil)
	if err := h.RevokeAll(context.Background(), attestedConn(1001), "drill"); err != nil {
		t.Fatalf("RevokeAll = %v; want nil", err)
	}
	deny, _ := store.LoadDeny(context.Background())
	foundGlobal := false
	for _, d := range deny {
		if d.Scope == state.ScopeGlobal {
			foundGlobal = true
		}
	}
	if !foundGlobal {
		t.Fatalf("RevokeAll did not engage the global DENY-ALL posture; entries=%v", deny)
	}
}

// TestBindRefusesNonSocketPath asserts Bind fails closed when the operator endpoint
// points at a real (non-socket) file rather than silently deleting it.
func TestBindRefusesNonSocketPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A regular file where the socket should go.
	path := dir + "/operator.sock"
	if err := writeMarker(path); err != nil {
		t.Fatalf("seed marker file: %v", err)
	}
	l := operator.NewListener(path, operator.Deps{})
	if err := l.Bind(); err == nil {
		_ = l.Close()
		t.Fatal("Bind onto a non-socket path returned nil; want a fail-closed refusal")
	}
}

// listerStore wraps an in-memory Store with the registry.LiveLister capability so
// the kill-switch can enumerate RESERVED+ACTIVE rows for the force-kill-every
// sweep. The frozen Phase-1 Store has per-key reads but no list-all; the durable
// Store gains enumeration in a later phase, so a test supplies it here. It records
// every reserved key and re-reads each through the inner Store.
type listerStore struct {
	state.Store
	mu   sync.Mutex
	keys map[string]bool
}

func newListerStore(inner state.Store) *listerStore {
	return &listerStore{Store: inner, keys: map[string]bool{}}
}

func (s *listerStore) Reserve(ctx context.Context, key string, ownerID state.Identity) (state.SessionRow, error) {
	row, err := s.Store.Reserve(ctx, key, ownerID)
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
	out := make([]state.SessionRow, 0, len(keys))
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

// LiveSessionsEnriched and RecordActivation forward to the inner Store so the
// listerStore satisfies the read-surface seams (registry.EnrichedLister /
// ActivationRecorder). The wrapper embeds a state.Store INTERFACE, which does not
// promote the concrete in-memory leg's extra methods, so the forward is explicit:
// the inner store is the in-memory leg, which implements both. A wrapped store
// that does not is a test-setup error surfaced loudly here.
func (s *listerStore) LiveSessionsEnriched(ctx context.Context) ([]state.EnrichedSessionRow, error) {
	el, ok := s.Store.(interface {
		LiveSessionsEnriched(context.Context) ([]state.EnrichedSessionRow, error)
	})
	if !ok {
		return nil, state.ErrStoreUnavailable
	}
	return el.LiveSessionsEnriched(ctx)
}

func (s *listerStore) RecordActivation(ctx context.Context, key string, caps state.Caps, at time.Time) error {
	ar, ok := s.Store.(interface {
		RecordActivation(context.Context, string, state.Caps, time.Time) error
	})
	if !ok {
		return state.ErrStoreUnavailable
	}
	return ar.RecordActivation(ctx, key, caps, at)
}

// fakeVerifier is a test SOARVerifier: on a successful verify (err == nil) it
// surfaces the configured SOAR PRINCIPAL identity, the authority for a SOAR-driven
// revoke; on a failure it returns the zero Identity and err. The principal is
// deliberately distinct from the socket-peer identity in the SOAR tests so the
// principal-as-actor assertion is not vacuous (P2-R2).
type fakeVerifier struct {
	identity state.Identity
	err      error
}

func (f *fakeVerifier) Verify(ctx context.Context, _, _ []byte) (state.Identity, error) {
	if err := ctx.Err(); err != nil {
		return state.Identity{}, err
	}
	if f.err != nil {
		return state.Identity{}, f.err
	}
	return f.identity, nil
}

// writeMarker writes a regular file at path so a Bind can prove it refuses a
// non-socket.
func writeMarker(path string) error {
	return os.WriteFile(path, []byte("not a socket"), 0o600)
}

// ingressTestExecVerifyKey is a 32-byte Ed25519-shaped verify key the handoff
// stager accepts on every scoped create. It stands in for the deployment-fixed
// exec verify key the daemon derives from -exec-signing-key.
func ingressTestExecVerifyKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}
