// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ocsf is the SOURCE side of the host audit fan-in for the control plane:
// it maps each privileged audit.Record onto a faithful-but-minimal OCSF v1.x event,
// hash-chains the serialized events into a tamper-evident per-source spine, and
// emits each one to a single EventWriter BEFORE the privileged action is
// acknowledged (fail-closed: a write failure denies the action). Control is a SOURCE
// on the fan-in — it does NOT own the bus, the WORM store, the SIEM, the
// transparency log, or the daily Merkle-head submission; those are the pluggable
// seams behind and downstream of EventWriter.
//
// The package depends one-directionally on the leaf audit port (for Action/Record)
// and on internal/state (for the injected Clock). The audit port does NOT import
// ocsf, so the leaf property holds: a layer that only needs the AuditSink contract
// never drags the OCSF mapping into its import graph.
//
// The OCSF class chosen for control-plane actions is "API Activity" (class_uid 6003)
// from the Application Activity (6) category of the public OCSF v1.x schema. The
// class is referenced by its numeric uid here, never by inlining vendor schema text
// — the same $ref discipline the audit-fanin AsyncAPI uses to reference the OCSF
// event class rather than copying it.
package ocsf

import (
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

const (
	// classUIDAPIActivity is the OCSF v1.x "API Activity" class uid (Application
	// Activity category 6, class 003 → 6003). Every control-plane privileged action
	// maps onto this single class; the specific verb is carried in activity_id. The
	// uid is the public-schema reference (by id, never by inlined text).
	classUIDAPIActivity uint32 = 6003

	// categoryUIDApplicationActivity is the OCSF category uid (6) the API Activity
	// class belongs to. It is the category_uid field on every emitted event.
	categoryUIDApplicationActivity uint32 = 6

	// schemaVersion is the OCSF schema version string the events conform to. It is
	// carried in metadata.version so a fan-in can pin which OCSF revision a source
	// emitted against.
	schemaVersion = "1.3.0"

	// productName is the OCSF metadata.product.name and log_provider for every event
	// this source emits.
	productName = "ocu-control"
)

// OCSF activity_id values (the verb within the API Activity class). These mirror the
// public OCSF activity-id enumeration for the class: Create/Read/Update/Delete plus
// the catch-all Other(99) for control-plane verbs that do not map to a CRUD slot.
const (
	activityCreate uint8 = 1
	activityUpdate uint8 = 3
	activityDelete uint8 = 4
	activityOther  uint8 = 99
)

// OCSF status_id values. A durable emit records the OUTCOME the action reached, not
// the durability of the record itself: a successful operator/lifecycle action is
// Success, and a create REFUSED at a pre-side-effect deny stage is Failure — the
// rejection record is durable (NFR-SEC-46/72), but the action it audits did not
// succeed, so it must not be marked Success.
const (
	statusSuccess uint8 = 1
	statusFailure uint8 = 2
)

// OCSF severity_id values. Informational is the default for a routine privileged
// action; a deployment-wide DENY-ALL revoke is raised to High because it is the most
// blast-radius operator action.
const (
	severityInformational uint8 = 1
	severityHigh          uint8 = 4
)

// User is the OCSF actor.user sub-object carrying the HOST-ATTESTED caller identity.
// Name is the host-derived caller principal and UIDAlt the host-derived tenant —
// both copied straight from the Record fields the layer above host-derived from the
// runtime-attested caller, NEVER a request-body hint. There is no token field here:
// the serializer reads only Record, none of whose fields is a cred.Token.
type User struct {
	Name   string `json:"name"`
	UIDAlt string `json:"uid_alt"`
}

// Session is the OCSF actor.session sub-object. UID is the host-derived reservation
// key the action targets (empty for a DENY-ALL that targets every session). It is a
// correlation handle, never an authority subject.
type Session struct {
	UID string `json:"uid"`
}

// Actor is the OCSF actor object: the host-attested identity plus the ingress the
// action arrived on. InvokedBy names the ingress ("operator" | "gateway"), copied
// from Record.Channel — the layer above set it from the resolved caller, never a
// body hint.
type Actor struct {
	User      User    `json:"user"`
	Session   Session `json:"session"`
	InvokedBy string  `json:"invoked_by"`
}

// Product is the OCSF metadata.product sub-object naming the emitting product.
type Product struct {
	Name string `json:"name"`
}

// Unmapped carries the control-plane fields that have no first-class OCSF slot: the
// action label, the operator-supplied reason text, and — on a destroy record only —
// the teardown revoke outcome. Reason is free-form trail context, never part of any
// authority decision. None of these fields is ever a token.
//
// RevokeOutcome is additive and OPTIONAL (omitempty): the finalizer step-1 revoke
// result ("marked_dead" / "already_dead" / "none_bound") on a destroy record, empty
// everywhere else. Like ChainBreak below, omitempty keeps the canonical payload of
// every event that does not carry it byte-identical to before the field existed, so
// the chain hash of all pre-existing event kinds is unchanged (proven by
// TestUnmappedRevokeOutcomeOmittedIsByteIdentical).
type Unmapped struct {
	Action        string `json:"action"`
	Reason        string `json:"reason"`
	RevokeOutcome string `json:"revoke_outcome,omitempty"`
}

// Metadata is the OCSF metadata object: the product, the OCSF schema version, the
// log provider, the per-event correlation handle (the host-derived key), and the
// unmapped control-plane fields.
type Metadata struct {
	Product        Product  `json:"product"`
	Version        string   `json:"version"`
	LogProvider    string   `json:"log_provider"`
	CorrelationUID string   `json:"correlation_uid"`
	Unmapped       Unmapped `json:"unmapped"`
}

// OCSFEvent is the faithful-but-minimal OCSF v1.x API-Activity event for one
// control-plane privileged action. Field order is fixed (encoding/json emits struct
// fields in declaration order), so json.Marshal is deterministic and the canonical
// hash over it is stable — there is no map in the hashed payload. The struct carries
// NO token field and no auth_token: the serializer reads only audit.Record, none of
// whose fields is a cred.Token, so a minted credential cannot reach an event by any
// path. The per-source sequence and the prior-hash chain link are carried OUT OF
// BAND in ChainEnvelope, never inside this OCSF payload — matching the audit-fanin
// contract that keeps sequence + chain metadata out-of-band from the OCSF $ref
// payload.
type OCSFEvent struct {
	ClassUID     uint32   `json:"class_uid"`
	CategoryUID  uint32   `json:"category_uid"`
	TypeUID      uint64   `json:"type_uid"`
	ActivityID   uint8    `json:"activity_id"`
	ActivityName string   `json:"activity_name"`
	Time         int64    `json:"time"`
	TimeDT       string   `json:"time_dt"`
	StatusID     uint8    `json:"status_id"`
	Status       string   `json:"status"`
	SeverityID   uint8    `json:"severity_id"`
	Actor        Actor    `json:"actor"`
	Metadata     Metadata `json:"metadata"`
	// ChainBreak is present ONLY on a system-emitted chain-break marker (a daemon
	// start whose resume tip was unreadable). It is a pointer with omitempty so a
	// normal privileged-action event omits it ENTIRELY — the field adds no bytes to
	// the canonical payload of a normal event, so its hash is byte-identical to
	// before this field existed (proven by TestNormalEventByteIdenticalWithChainBreakField).
	// A chain-break marker is the ONLY event that legitimately re-anchors the spine
	// at genesis mid-file; ValidateChain accepts a mid-file genesis record only when
	// this marker is present, so a silent re-anchor (tamper) is rejected.
	ChainBreak *ChainBreakInfo `json:"chain_break,omitempty"`
}

// ChainBreakInfo is the payload of a chain-break marker: the resume discontinuity a
// daemon start observed. ObservedPriorTip records what the boot actually read at the
// file tail — the last valid hash it could recover, or the literal "unreadable" when
// the tail could not be parsed at all — so the discontinuity is documented in-band and
// detectable post-hoc. A marker's own envelope re-anchors at genesisPriorHash (there
// is no trustworthy prior tip to link to), which is legitimate ONLY because this field
// marks it; ValidateChain enforces that pairing.
type ChainBreakInfo struct {
	// ObservedPriorTip is the tail state the boot observed. It is NEVER empty on a
	// chain-break marker: a recovered-but-decoupled hash, or the literal "unreadable"
	// when the tail did not parse. The non-empty invariant is enforced at construction
	// and re-checked in ValidateChain.
	ObservedPriorTip string `json:"observed_prior_tip"`
}

// ChainBreakUnreadable is the ObservedPriorTip sentinel when the file tail could not be
// parsed into any hash at all (a torn write, a truncated line). It keeps the field
// non-empty so the chain_break⇒observed_prior_tip-non-empty invariant holds even when
// nothing recoverable was read.
const ChainBreakUnreadable = "unreadable"

// activityFor maps a privileged audit.Action onto its OCSF activity_id and a
// human-readable activity_name. Create-commit is Create(1); destroy is Delete(4);
// the revoke / denylist-edit / quota-override / retention-policy / resume-global
// actions are state-mutating operator controls that map to Update(3); the
// create-rejected refusal and the create-resume reuse each produced or changed no
// resource and so map to Other(99) by explicit cases; an unknown action falls to
// Other(99) so a forgotten arm surfaces as an explicit Other rather than a silent
// mislabel. The name always reflects the Action.String label so the event is
// self-describing even on the Other path.
func activityFor(a audit.Action) (uint8, string) {
	switch a {
	case audit.ActionCreateCommit:
		return activityCreate, a.String()
	case audit.ActionDestroy:
		return activityDelete, a.String()
	case audit.ActionRevokeOne, audit.ActionRevokeAll,
		audit.ActionEditDenylist, audit.ActionOverrideQuota, audit.ActionRetentionPolicy,
		audit.ActionResumeGlobal,
		audit.ActionMCPKeyCreate, audit.ActionMCPKeyRevoke:
		return activityUpdate, a.String()
	case audit.ActionCreateResume:
		// A resume neither provisions a new resource (Create), mutates one (Update),
		// nor tears one down (Delete): the session is already ACTIVE and unchanged —
		// the record attests that the live session was re-addressed and returned, not
		// altered. Its honest CRUD slot is therefore Other(99) by an EXPLICIT case, the
		// same faithful "no CRUD effect" slot the create-rejected record takes (a
		// refusal produced no resource; a resume changed none). The name still reflects
		// the Action label ("create_resume"), so the Other event is self-describing.
		return activityOther, a.String()
	case audit.ActionExec:
		// One exec tool-call spawns a process in the session's guest — the created
		// resource is the guest child process, so the honest CRUD slot is Create.
		// The name stays the Action label ("exec"), so the record is
		// self-describing next to the session-create Create events.
		return activityCreate, a.String()
	case audit.ActionCreateRejected:
		// A refused create produced no resource, so it has no CRUD slot: it maps to
		// Other(99) by an EXPLICIT case (not the unknown fall-through). The name still
		// reflects the Action label, so the Other event is self-describing.
		return activityOther, a.String()
	default:
		return activityOther, a.String()
	}
}

// severityFor maps a privileged action onto its OCSF severity_id. A deployment-wide
// DENY-ALL revoke (ActionRevokeAll) is the highest-blast-radius operator action and
// is raised to High; every other privileged action is Informational.
func severityFor(a audit.Action) uint8 {
	if a == audit.ActionRevokeAll {
		return severityHigh
	}
	return severityInformational
}

// statusFor maps a privileged audit.Action onto its OCSF status_id. A create-rejected
// is the durable record of a REFUSED action, so its honest status is Failure(2) — the
// record is durable but the audited action did not succeed. Every other privileged
// action records a durable Success(1) outcome.
func statusFor(a audit.Action) uint8 {
	if a == audit.ActionCreateRejected {
		return statusFailure
	}
	return statusSuccess
}

// statusName renders an OCSF status_id as its label. Success and Failure are the two
// outcomes a durable control-plane record carries (a successful action vs an audited
// refusal); an unexpected id renders as "Unknown" rather than an empty string.
func statusName(id uint8) string {
	switch id {
	case statusSuccess:
		return "Success"
	case statusFailure:
		return "Failure"
	default:
		return "Unknown"
	}
}

// buildEvent maps a single audit.Record onto an OCSFEvent at the instant clk.Now()
// reports. The time fields are derived from the INJECTED Clock — never time.Now —
// and the type_uid follows the OCSF rule type_uid = class_uid*100 + activity_id. The
// actor is the host-attested identity copied straight from the Record; no field is
// ever populated from a body hint, and no field is a token. The sequence and chain
// link are NOT set here — they are the sink's out-of-band ChainEnvelope.
func buildEvent(clk state.Clock, rec audit.Record) OCSFEvent {
	now := clk.Now()
	activityID, activityName := activityFor(rec.Action)
	typeUID := uint64(classUIDAPIActivity)*100 + uint64(activityID)
	sid := statusFor(rec.Action)

	return OCSFEvent{
		ClassUID:     classUIDAPIActivity,
		CategoryUID:  categoryUIDApplicationActivity,
		TypeUID:      typeUID,
		ActivityID:   activityID,
		ActivityName: activityName,
		Time:         now.UnixMilli(),
		TimeDT:       now.UTC().Format(time.RFC3339Nano),
		StatusID:     sid,
		Status:       statusName(sid),
		SeverityID:   severityFor(rec.Action),
		Actor: Actor{
			User:      User{Name: rec.Caller, UIDAlt: rec.Tenant},
			Session:   Session{UID: rec.Key},
			InvokedBy: rec.Channel,
		},
		Metadata: Metadata{
			Product:        Product{Name: productName},
			Version:        schemaVersion,
			LogProvider:    productName,
			CorrelationUID: rec.Key,
			Unmapped: Unmapped{
				Action:        rec.Action.String(),
				Reason:        rec.Reason,
				RevokeOutcome: rec.RevokeOutcome,
			},
		},
	}
}

// chainBreakActionLabel is the self-describing action label of a chain-break marker.
// It is not an audit.Action (a chain break is a system event, not a privileged
// operator action, so it never enters the SEC-45 Action set), so its label is a
// standalone constant rather than an Action.String value.
const chainBreakActionLabel = "chain_break"

// buildChainBreakEvent maps a resume discontinuity onto an OCSFEvent carrying the
// ChainBreak marker. observedTip is what the boot read at the tail (a recovered hash
// or ChainBreakUnreadable); it is stored verbatim so the discontinuity is documented
// in-band. The event is a system daemon-start marker: activity Other, High severity
// (a chain break is a security-relevant integrity event), no actor identity (there is
// no privileged caller — the daemon itself emitted it). It is the ONLY event that
// legitimately carries a genesis prior-hash mid-file; ValidateChain enforces the
// pairing with the marker.
func buildChainBreakEvent(clk state.Clock, observedTip string) OCSFEvent {
	now := clk.Now()
	typeUID := uint64(classUIDAPIActivity)*100 + uint64(activityOther)
	if observedTip == "" {
		// Defence in depth: the field must never be empty on a marker. The caller
		// passes a recovered hash or ChainBreakUnreadable; an empty value is coerced to
		// the sentinel so the chain_break⇒observed_prior_tip-non-empty invariant holds.
		observedTip = ChainBreakUnreadable
	}
	return OCSFEvent{
		ClassUID:     classUIDAPIActivity,
		CategoryUID:  categoryUIDApplicationActivity,
		TypeUID:      typeUID,
		ActivityID:   activityOther,
		ActivityName: chainBreakActionLabel,
		Time:         now.UnixMilli(),
		TimeDT:       now.UTC().Format(time.RFC3339Nano),
		StatusID:     statusSuccess,
		Status:       statusName(statusSuccess),
		SeverityID:   severityHigh,
		Actor: Actor{
			User:      User{},
			Session:   Session{},
			InvokedBy: "system",
		},
		Metadata: Metadata{
			Product:        Product{Name: productName},
			Version:        schemaVersion,
			LogProvider:    productName,
			CorrelationUID: "",
			Unmapped: Unmapped{
				Action: chainBreakActionLabel,
				Reason: "audit chain resume discontinuity: prior tip " + observedTip,
			},
		},
		ChainBreak: &ChainBreakInfo{ObservedPriorTip: observedTip},
	}
}
