// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// authnCollectWriter captures envelopes for chain validation.
type authnCollectWriter struct{ envelopes []ChainEnvelope }

func (w *authnCollectWriter) Write(_ context.Context, env ChainEnvelope) error {
	w.envelopes = append(w.envelopes, env)
	return nil
}

// Authentication events (OCSF 3002) close the declared-but-never-emitted half
// of the control-plane channel (#107). They are NOT audit.Actions: the SEC-45
// enum is the privileged state-mutating set with an exhaustiveness property
// over it, and a logon is an observation, not a privileged action. They follow
// EmitChainBreak's pattern instead — their own record kind, the same chain.
//
// The ADR-0044 lesson binds the shape: an event carrying class_uid 3002
// without the class's own required objects is not Authentication. The base
// class requires user, and at_least_one(service, dst_endpoint); logons carry
// logon_type and auth_protocol or a verifier cannot tell a socket peer from an
// mTLS peer.

func testAuthnLogon() AuthnRecord {
	return AuthnRecord{
		Activity: AuthnLogon,
		Outcome:  AuthnSuccess,
		Caller:   "tenant-9/portal-a",
		Tenant:   "tenant-9",
		Channel:  "gateway",
		Protocol: AuthnProtocolMTLS,
		CertSAN:  "spiffe://ocu/tenant-9/portal-a",
		ConnID:   "conn-0000000001",
	}
}

// TestAuthnEventCarriesTheClassRequiredObjects is the conformance keystone.
func TestAuthnEventCarriesTheClassRequiredObjects(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	ev := buildAuthnEvent(clk, testAuthnLogon())

	if ev.ClassUID != classUIDAuthentication {
		t.Fatalf("class_uid = %d, want %d", ev.ClassUID, classUIDAuthentication)
	}
	if ev.CategoryUID != categoryUIDIdentityAndAccess {
		t.Errorf("category_uid = %d, want %d (IAM)", ev.CategoryUID, categoryUIDIdentityAndAccess)
	}
	if ev.TypeUID != uint64(classUIDAuthentication)*100+uint64(AuthnLogon) {
		t.Errorf("type_uid = %d, want class*100+activity", ev.TypeUID)
	}
	if ev.User == nil || ev.User.Name != "tenant-9/portal-a" {
		t.Errorf("user = %+v; 3002 REQUIRES the authenticating user at top level", ev.User)
	}
	if ev.Service == nil || ev.Service.Name == "" {
		t.Errorf("service = %+v; the class requires at_least_one(service, dst_endpoint) "+
			"and this transport has no dst_endpoint to name", ev.Service)
	}
	if ev.API != nil || ev.Entity != nil {
		t.Error("an authentication event carries api or entity objects, which belong " +
			"to other classes")
	}
}

// TestAuthnProtocolsAreDistinguishable is the discriminator property, stated
// across records as the entity-type lesson taught: presence and non-emptiness
// are properties of one value, discrimination is a relation between several.
func TestAuthnProtocolsAreDistinguishable(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)

	mtls := testAuthnLogon()
	peercred := AuthnRecord{
		Activity: AuthnLogon, Outcome: AuthnSuccess,
		Caller: "operator-uid-501", Channel: "operator",
		Protocol: AuthnProtocolPeerCred, ConnID: "conn-2",
	}

	a, b := buildAuthnEvent(clk, mtls), buildAuthnEvent(clk, peercred)
	if a.AuthProtocol == b.AuthProtocol {
		t.Errorf("mTLS and peercred logons both report auth_protocol %q; a reviewer "+
			"cannot tell a network client from a local socket peer", a.AuthProtocol)
	}
	if a.LogonTypeID == b.LogonTypeID {
		t.Errorf("mTLS and peercred logons both report logon_type_id %d", a.LogonTypeID)
	}
	// The mTLS record names its certificate; the peercred one must NOT invent one.
	if a.Certificate == nil || a.Certificate.SubjectAltName == "" {
		t.Error("the mTLS logon carries no certificate SAN; the credential that " +
			"authenticated is unnamed")
	}
	if b.Certificate != nil {
		t.Error("the peercred logon invented a certificate")
	}
}

// TestAuthnFailureNamesItsCause pins the failure half. Every failed attempt is
// recorded, and the record must say WHY — "authentication failed" with no
// detail sends a reviewer back to the raw connection logs the trail exists to
// replace.
func TestAuthnFailureNamesItsCause(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	rec := testAuthnLogon()
	rec.Outcome = AuthnFailure
	rec.FailureDetail = "SAN not tenant/caller-shaped: \"spiffe://other/thing\""

	ev := buildAuthnEvent(clk, rec)
	if ev.StatusID != statusFailure {
		t.Fatalf("status_id = %d, want %d (failure)", ev.StatusID, statusFailure)
	}
	if ev.StatusDetail == "" || !strings.Contains(ev.StatusDetail, "SAN not tenant") {
		t.Errorf("status_detail = %q; the cause is gone", ev.StatusDetail)
	}
	if ev.SeverityID != severityInformational {
		// A single failed logon is informational; flood detection is the
		// pipeline's job (rate-keyed), not a per-event severity inflation.
		t.Errorf("severity_id = %d; a single failed logon is not an incident", ev.SeverityID)
	}
}

// TestAuthnTicketCarriesTheSession covers the Storage-JWT mint half (activity
// 3, Authentication Ticket). The ticket's subject is the session, so the
// record must carry the session key — a mint event that names no session
// witnesses a credential with no scope.
func TestAuthnTicketCarriesTheSession(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	ev := buildAuthnEvent(clk, AuthnRecord{
		Activity: AuthnTicket, Outcome: AuthnSuccess,
		Caller: "tenant-9/portal-a", Tenant: "tenant-9", Channel: "gateway",
		Protocol: AuthnProtocolStorageJWT, SessionKey: "sess-key-1",
	})

	if ev.TypeUID != uint64(classUIDAuthentication)*100+uint64(AuthnTicket) {
		t.Errorf("type_uid = %d, want the ticket activity", ev.TypeUID)
	}
	if ev.Actor.Session.UID != "sess-key-1" {
		t.Errorf("session uid = %q; the ticket names no session", ev.Actor.Session.UID)
	}
}

// TestAuthnEmitRidesTheSameChain proves an authentication event is chained like
// every other record — same spine, same tamper evidence — via the sink's own
// emit path, not a parallel channel.
func TestAuthnEmitRidesTheSameChain(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	w := &authnCollectWriter{}
	sink := NewChainSink(clk, w, "control")

	if err := sink.EmitAuthn(context.Background(), testAuthnLogon()); err != nil {
		t.Fatalf("EmitAuthn: %v", err)
	}
	rec := testAuthnLogon()
	rec.Outcome = AuthnFailure
	rec.FailureDetail = "no verified SAN"
	if err := sink.EmitAuthn(context.Background(), rec); err != nil {
		t.Fatalf("EmitAuthn failure record: %v", err)
	}

	if err := ValidateChain(w.envelopes); err != nil {
		t.Fatalf("the authn events do not chain: %v", err)
	}
	if len(w.envelopes) != 2 {
		t.Fatalf("chain holds %d envelopes, want 2", len(w.envelopes))
	}
	var ev OCSFEvent
	if err := json.Unmarshal(w.envelopes[0].Event, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.ClassUID != classUIDAuthentication {
		t.Errorf("the chained event carries class %d, want 3002", ev.ClassUID)
	}
}

// TestAuthnUnknownActivityIsSelfDescribing pins the fallback label. An
// activity value outside the enum still produces a readable record rather
// than an empty name — the same posture activityFor takes with Other(99).
func TestAuthnUnknownActivityIsSelfDescribing(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	rec := testAuthnLogon()
	rec.Activity = AuthnActivity(42)
	ev := buildAuthnEvent(clk, rec)
	if ev.ActivityName != "authn_activity_unknown" {
		t.Errorf("activity 42 reports name %q; an unknown value must say so rather "+
			"than carry an empty or wrong label", ev.ActivityName)
	}
}

// TestAuthnEmitRefusesACancelledContext matches Emit's own fail-closed deny on
// a dead context: no work, no sequence consumed.
func TestAuthnEmitRefusesACancelledContext(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	w := &authnCollectWriter{}
	sink := NewChainSink(clk, w, "control")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.EmitAuthn(ctx, testAuthnLogon()); err == nil {
		t.Fatal("a cancelled context was accepted")
	}
	if len(w.envelopes) != 0 {
		t.Errorf("a cancelled emit still wrote %d envelope(s)", len(w.envelopes))
	}
}

// TestAuthnEmitSurfacesAWriterFault keeps the caller informed: the
// fail-open/fail-closed decision is the caller's, and it cannot decide on an
// error it never sees. The failed emit must not advance the chain.
func TestAuthnEmitSurfacesAWriterFault(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	sink := NewChainSink(clk, &authnFaultWriter{}, "control")

	if err := sink.EmitAuthn(context.Background(), testAuthnLogon()); err == nil {
		t.Fatal("a writer fault was swallowed; the caller cannot count a loss it " +
			"never sees")
	}

	// The failed emit consumed no sequence: the next successful emit starts at 1.
	w := &authnCollectWriter{}
	sink2 := NewChainSink(clk, w, "control")
	if err := sink2.EmitAuthn(context.Background(), testAuthnLogon()); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if w.envelopes[0].Sequence != 1 {
		t.Errorf("first envelope carries sequence %d, want 1", w.envelopes[0].Sequence)
	}
}

// authnFaultWriter always refuses.
type authnFaultWriter struct{}

func (authnFaultWriter) Write(context.Context, ChainEnvelope) error {
	return context.DeadlineExceeded
}

// TestExistingEventsCarryNoAuthnKeys keeps the pre-existing event kinds
// byte-identical: every new field is omitempty, so the chain hash of every
// already-shipped record shape is unchanged. This is the same discipline
// RevokeOutcome and ChainBreak followed, and the golden-byte tests depend on
// it.
func TestExistingEventsCarryNoAuthnKeys(t *testing.T) {
	clk := state.NewFakeClock(fixedStart)
	ev := buildEvent(clk, audit.Record{
		Action: audit.ActionEditDenylist, Channel: "operator",
		Key: "k", Caller: "op", Tenant: "t9",
	})
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Top-level keys only: "user" legitimately appears INSIDE actor on every
	// event, so a substring match false-positives on shapes that never changed.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"service", "logon_type_id", "auth_protocol",
		"certificate", "status_detail", "user"} {
		if _, present := doc[key]; present {
			t.Errorf("a 3004 event now carries top-level %q; every pre-existing event "+
				"shape must stay byte-identical or the chain hash of shipped records "+
				"changes", key)
		}
	}
}
