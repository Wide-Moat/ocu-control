// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Authentication events (OCSF 3002) — the declared-but-never-emitted half of
// the control-plane channel (#107, ADR-0044).
//
// An authentication is an OBSERVATION, not a privileged action: it does not
// join the SEC-45 audit.Action enum, whose exhaustiveness property covers the
// privileged state-mutating set. It follows EmitChainBreak's pattern instead —
// its own record kind, riding the same hash-chained spine.
//
// Granularity is per authentication ACT. The TLS handshake and the kernel's
// SO_PEERCRED attestation are the acts; per-request Resolve re-reads an
// established attestation and verifies nothing new, so a per-request event
// would fabricate authentications that never happened. Successes are emitted
// once per connection; failures always.

const (
	// classUIDAuthentication is the OCSF v1.x "Authentication" class uid (IAM
	// category 3, class 002 -> 3002).
	classUIDAuthentication uint32 = 3002
)

// AuthnActivity is the OCSF 3002 activity_id.
type AuthnActivity uint8

const (
	// AuthnLogon is activity 1: a principal authenticated to the plane.
	AuthnLogon AuthnActivity = 1
	// AuthnTicket is activity 3 (Authentication Ticket): the plane issued a
	// scoped credential — the per-session Storage-JWT mint (NFR-SEC-72's
	// "automatic per-session lease issue").
	AuthnTicket AuthnActivity = 3
)

// AuthnOutcome is the result of the act.
type AuthnOutcome uint8

const (
	AuthnSuccess AuthnOutcome = iota
	AuthnFailure
)

// AuthnProtocol names how the principal authenticated. The value is the
// discriminator a reviewer filters on: a network client and a local socket
// peer are different threat surfaces, and one label for both hides which one
// is under attack.
type AuthnProtocol string

const (
	// AuthnProtocolMTLS is the gateway service channel: a verified client
	// certificate chain, identity from the SAN.
	AuthnProtocolMTLS AuthnProtocol = "mtls-x509"
	// AuthnProtocolPeerCred is the operator Unix socket: kernel-vouched
	// uid/gid/pid via SO_PEERCRED.
	AuthnProtocolPeerCred AuthnProtocol = "unix-peercred" //nolint:gosec // G101: protocol label ("cred" heuristic), not a credential
	// AuthnProtocolStorageJWT is the per-session lease mint (activity 3).
	AuthnProtocolStorageJWT AuthnProtocol = "storage-jwt"
)

// AuthnRecord is one authentication act, success or failure.
//
// None of its fields is ever a token or a key: the certificate is named by its
// SAN, the ticket by the session it scopes.
type AuthnRecord struct {
	Activity AuthnActivity
	Outcome  AuthnOutcome
	// Caller is the resolved principal on success, or the best available
	// identity sketch on failure (a failure often has no resolved identity).
	Caller string
	// Tenant is the host-derived tenant, when resolution got that far.
	Tenant string
	// Channel is the ingress the act arrived on ("gateway" | "operator").
	Channel string
	// Protocol names how the principal authenticated.
	Protocol AuthnProtocol
	// CertSAN is the verified certificate SAN for mTLS acts; empty otherwise.
	// A peercred logon must not invent a certificate.
	CertSAN string
	// ConnID is the host-assigned connection identity the success latch keys
	// on; it correlates the logon with the actions that follow on the same
	// connection.
	ConnID string
	// SessionKey scopes an AuthnTicket to the session it was minted for.
	SessionKey string
	// FailureDetail names WHY a failed act failed. Empty on success.
	FailureDetail string
}

// logonTypeID is the OCSF logon_type_id for the protocol: Network(3) for a
// TLS client, Interactive(2) for the local operator socket.
func logonTypeID(p AuthnProtocol) uint8 {
	if p == AuthnProtocolPeerCred {
		return 2
	}
	return 3
}

// buildAuthnEvent maps one act onto a conformant 3002 event: the class's own
// required objects (user; service, since this transport has no dst_endpoint to
// name), the protocol discriminators, and the failure cause.
func buildAuthnEvent(clk state.Clock, rec AuthnRecord) OCSFEvent {
	now := clk.Now()

	sid := statusSuccess
	if rec.Outcome == AuthnFailure {
		sid = statusFailure
	}

	var cert *Certificate
	if rec.CertSAN != "" {
		cert = &Certificate{SubjectAltName: rec.CertSAN}
	}

	lt := logonTypeID(rec.Protocol)

	return OCSFEvent{
		ClassUID:     classUIDAuthentication,
		CategoryUID:  categoryUIDIdentityAndAccess,
		TypeUID:      uint64(classUIDAuthentication)*100 + uint64(rec.Activity),
		ActivityID:   uint8(rec.Activity),
		ActivityName: authnActivityName(rec.Activity),
		Time:         now.UnixMilli(),
		TimeDT:       now.UTC().Format(time.RFC3339Nano),
		StatusID:     sid,
		Status:       statusName(sid),
		StatusDetail: rec.FailureDetail,
		SeverityID:   severityInformational,
		User:         &User{Name: rec.Caller, UIDAlt: rec.Tenant},
		Service:      &Service{Name: productName},
		LogonTypeID:  lt,
		AuthProtocol: string(rec.Protocol),
		Certificate:  cert,
		Actor: Actor{
			User:      User{Name: rec.Caller, UIDAlt: rec.Tenant},
			Session:   Session{UID: rec.SessionKey},
			InvokedBy: rec.Channel,
		},
		Metadata: Metadata{
			Product:        Product{Name: productName},
			Version:        schemaVersion,
			LogProvider:    productName,
			CorrelationUID: rec.ConnID,
			Unmapped: Unmapped{
				Action: "authn_" + authnActivityName(rec.Activity),
			},
		},
	}
}

func authnActivityName(a AuthnActivity) string {
	switch a {
	case AuthnLogon:
		return "logon"
	case AuthnTicket:
		return "ticket"
	}
	return "authn_activity_unknown"
}

// EmitAuthn chains one authentication event onto the same spine every other
// record rides — same sequence space, same tamper evidence, no parallel
// channel. The fail-open/fail-closed decision belongs to the CALLER: the logon
// producer path counts a loss and continues (NFR-SEC-79), the in-pipeline mint
// treats an error as a deny like the create stage it lives in.
func (s *ChainSink) EmitAuthn(ctx context.Context, rec AuthnRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ev := buildAuthnEvent(s.clk, rec)
	body, err := canonicalize(ev)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitLocked(ctx, body, s.priorTip)
}
