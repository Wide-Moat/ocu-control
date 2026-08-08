// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/admission"
	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/handoff"
	"github.com/Wide-Moat/ocu-control/internal/lifecycle"
	"github.com/Wide-Moat/ocu-control/internal/quota"
	"github.com/Wide-Moat/ocu-control/internal/registry"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// The Storage-JWT mint is the "Session JWT issue" half of the contract's
// Authentication message (#107): an OCSF 3002 activity-3 ticket, one per
// storage-scoped create. Unlike the connection logons it is FAIL-CLOSED —
// NFR-SEC-72 names the per-session lease issue, and the mint sits inside the
// create pipeline that already refuses on an unrecorded create_commit.
//
// The seam is a plain func(ctx, sessionKey) so lifecycle stays ignorant of
// OCSF: the record's semantics live at the daemon's composition point, and the
// audit port's leaf property (it never imports ocsf) is untouched.

// ticketRecorder captures the seam's calls.
type ticketRecorder struct {
	mu   sync.Mutex
	keys []string
	err  error
}

func (r *ticketRecorder) emit(_ context.Context, sessionKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.keys = append(r.keys, sessionKey)
	return nil
}

func newTicketManager(t *testing.T, rec *ticketRecorder) *lifecycle.Manager {
	t.Helper()
	clk := state.NewFakeClock(lifeStart)
	inner := state.NewInMemory(clk)
	store := newListerStore(inner)
	provider := newRecordingProvider()
	signer, _ := newTestSigner(t, clk)

	return lifecycle.NewManager(lifecycle.ManagerDeps{
		Custodian:       registry.NewCustodian(store),
		Provider:        provider,
		Clock:           clk,
		Quota:           quota.NewGate(store, clk, generousLimits()),
		Handoff:         handoff.NewStager(t.TempDir()),
		Audit:           audit.NewRecordingFake(),
		Profile:         admission.ProfileTrustedOperator,
		Tier:            runtime.TierRunc,
		AllowedImages:   []string{testGuestImage},
		ExecVerifyKey:   pub32(),
		Signer:          signer,
		Push:            newRecordingPusher(),
		ServiceURL:      testServiceURL,
		CACertPEM:       testCACert,
		MountDefaults:   testMountDefaults(t),
		StorageScope:    lifecycle.StorageScope{Workspace: "ws", Org: "org", Intent: cred.IntentWrite},
		GrantedIntents:  lifecycle.NewIntentCeiling(cred.IntentRead, cred.IntentWrite),
		AuthnTicketEmit: rec.emit,
	})
}

// TestMintEmitsOneTicketPerCreate binds the seam: a storage-scoped create
// records exactly one ticket, carrying the HOST-DERIVED session key.
func TestMintEmitsOneTicketPerCreate(t *testing.T) {
	t.Parallel()
	rec := &ticketRecorder{}
	mgr := newTicketManager(t, rec)

	sess, err := mgr.Create(context.Background(), intentCreateInput("tkt-session", false))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.keys) != 1 {
		t.Fatalf("the create emitted %d ticket(s), want 1", len(rec.keys))
	}
	if rec.keys[0] == "" || rec.keys[0] != sess.Key {
		t.Errorf("the ticket names session %q, the create returned %q — the ticket "+
			"must carry the host-derived key, or the credential correlates to nothing",
			rec.keys[0], sess.Key)
	}
}

// TestMintTicketEmitFailureFailsTheCreate is the fail-closed arm, and the
// contrast with the fail-open logons is deliberate: the ticket is not an
// observation of someone else's act, it is the plane ISSUING a credential, and
// a credential whose issuance the trail does not hold is exactly what
// NFR-SEC-72's lease-issue row forbids.
func TestMintTicketEmitFailureFailsTheCreate(t *testing.T) {
	t.Parallel()
	rec := &ticketRecorder{err: errors.New("audit spine unavailable")}
	mgr := newTicketManager(t, rec)

	_, err := mgr.Create(context.Background(), intentCreateInput("tkt-fail", false))
	if err == nil {
		t.Fatal("a create whose ticket record was refused still succeeded; a " +
			"credential now exists that the trail does not hold")
	}
	if !strings.Contains(err.Error(), "audit spine unavailable") {
		t.Errorf("the refusal is %v, which does not surface the record failure", err)
	}
}

// TestNoScopeCreateEmitsNoTicket keeps the ticket bound to an actual mint. A
// pure compute/exec session mints no Storage-JWT, so a ticket for it would
// witness a credential that does not exist.
func TestNoScopeCreateEmitsNoTicket(t *testing.T) {
	t.Parallel()
	rec := &ticketRecorder{}
	mgr := newTicketManager(t, rec)

	in := lifecycle.CreateInput{
		Caller:      testCaller,
		SessionHint: "tkt-noscope",
		Image:       testGuestImage,
		Mount:       runtime.MountIntent{},
		Egress:      runtime.EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store"},
		Resources:   runtime.ResourceCaps{CPUCores: 1, MemoryBytes: 1 << 30},
	}
	if _, err := mgr.Create(context.Background(), in); err != nil {
		t.Fatalf("no-scope Create: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.keys) != 0 {
		t.Errorf("a no-scope create emitted %d ticket(s); the ticket would witness a "+
			"credential that was never minted", len(rec.keys))
	}
}
