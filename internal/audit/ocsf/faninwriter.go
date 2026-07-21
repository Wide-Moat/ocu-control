// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Wide-Moat/ocu-control/internal/audit"
)

// This file is the source half of the component-07 F10 audit fan-in: a
// composite EventWriter that mirrors each ChainEnvelope to the local durable
// sink AND publishes the event to the central ocu-audit ingest, on the ack path
// (P7-R3). ChainSink stays the durable per-source SEQUENCE authority (the wire's
// 409 needs a crash-resumable monotonic counter, which only the local chained
// file provides); this writer sits behind ChainSink at the EventWriter seam and
// adds the publish leg, per ADR-0009 and the sink.go seam contract.

// Publisher is the central-ingest publish leg. ocu-audit's pkg/publish.Client
// satisfies it. It is an interface here so control does not hard-import the
// ocu-audit client into this package and so the composite is unit-testable
// against a stub.
//
// Publish returns nil ONLY when the ingest durably committed the event (a 200
// after its WAL fsync). Any non-nil error means NOT committed: the composite
// fails closed so the caller's existing ErrAuditWriteFailed branch denies the
// privileged action.
type Publisher interface {
	// Publish sends one pre-chain event to the source's channel. The wire body
	// omits source/prev_hash/chain_hash (the pipeline authors them; the source
	// is the mTLS client-cert CN); the caller has already stripped them.
	Publish(ctx context.Context, wire PublishWire) error
}

// PublishWire is the wire envelope a source POSTs, mirroring the frozen contract
// (ocu-audit docs/wire-surface.md + contracts/audit/audit-fanin.asyncapi.yaml,
// NFR-MAINT-AUDIT-SCHEMA). It carries the OCU mandatory audit fields as DISCRETE
// top-level values -- trace_id is the SIEM cross-surface correlation key, so it
// must be a flat field, never buried in the payload -- plus the per-source
// Sequence (the ingest 409s a non-increasing value) and the OCSF event as the
// payload. It deliberately has no source/prior_hash/chain_hash: the pipeline
// authors the chain and derives the source from the mTLS client-cert CN
// (INV-1/INV-3). The discrete fields are populated by ChainSink from the
// audit.Record it already holds (Caller->ActorID, Key->SessionID/Resource,
// Action->Action, outcome->Outcome) plus a trace_id threaded in at the caller;
// keeping our own struct keeps this package free of an ocu-audit import, and an
// adapter in the wiring layer copies it 1:1 onto the ocu-audit client Envelope.
type PublishWire struct {
	TraceID   string          `json:"trace_id"`
	SessionID string          `json:"session_id"`
	ActorID   string          `json:"actor_id"`
	Resource  string          `json:"resource"`
	Action    string          `json:"action"`
	Outcome   string          `json:"outcome"`
	Sequence  uint64          `json:"sequence"`
	Payload   json.RawMessage `json:"payload"`
}

// FanInWriter is a composite EventWriter: it writes to the local durable sink
// first, then publishes to the central ingest. It is fail-closed on either leg
// (P7-R3): a local write failure OR a publish failure returns an error, which
// ChainSink wraps as audit.ErrAuditWriteFailed and the caller denies the action.
//
// Ordering is local-then-publish deliberately. If the publish leg fails after a
// successful local write, the local mirror carries a committed tail event that
// the central chain does not; on the caller's retry with the SAME sequence, the
// ingest treats the duplicate as already-committed (idempotent 409/200 dedup)
// and the local mirror tolerates the same-sequence tail artifact on resume. The
// inverse order (publish-then-file) could commit to canon an action the local
// write then rejects, which P7-R3 forbids: the pipeline commit governs the ack,
// so the local mirror is the leg allowed to carry a benign same-sequence tail.
type FanInWriter struct {
	local EventWriter
	pub   Publisher
}

var _ EventWriter = (*FanInWriter)(nil)

// auditSeam is the shape the daemon's audit writer interface requires
// (cmd/ocu-controld auditWriter = EventWriter + Close). It is asserted here so a
// missing Close on the composite fails THIS package's build, not the injection
// site's: the fan-in writer must be a drop-in for the bare FileSink at that seam.
type auditSeam interface {
	EventWriter
	Close() error
}

var _ auditSeam = (*FanInWriter)(nil)

// NewFanInWriter composes a local EventWriter with a central Publisher. Both are
// required; a nil argument is a construction error, not a deferred write
// failure, because a source with no publish leg silently regresses to the
// forensic-only mirror this fan-in exists to fix.
func NewFanInWriter(local EventWriter, pub Publisher) (*FanInWriter, error) {
	if local == nil {
		return nil, errors.New("ocsf: fan-in writer requires a local EventWriter")
	}
	if pub == nil {
		return nil, errors.New("ocsf: fan-in writer requires a central Publisher")
	}
	return &FanInWriter{local: local, pub: pub}, nil
}

// Write mirrors env to the local sink, then publishes it. It returns nil only
// when BOTH legs succeeded. A non-nil error from either leg is the fail-closed
// signal: the sequence and prior-hash tip do NOT advance in ChainSink, and the
// caller denies the privileged action.
func (w *FanInWriter) Write(ctx context.Context, env ChainEnvelope) error {
	// Local leg first: the durable sequence/tip authority. If it fails, do not
	// publish (there is no committed local record to reconcile against).
	if err := w.local.Write(ctx, env); err != nil {
		return err // already an ocsf sink error; ChainSink wraps it
	}
	// Publish leg: strip the pipeline-authored fields, keep the sequence and the
	// canonical event bytes. A non-200 (mapped to a non-nil error by the
	// Publisher) fails the whole Write closed.
	if err := w.pub.Publish(ctx, toPublishWire(env)); err != nil {
		return fmt.Errorf("ocsf: fan-in publish (seq=%d): %w", env.Sequence, err)
	}
	return nil
}

// Close runs the shutdown flush of the durable-emit seam. The daemon's audit
// writer interface is EventWriter + Close (cmd/ocu-controld: the FileSink already
// satisfies it, and buildAuditWriter runs Close on shutdown to flush the final
// fsync). When the fan-in composite REPLACES the bare FileSink at that seam, it
// must forward Close to the local sink so the final fsync still runs -- otherwise
// the last durably-written envelope's fsync is lost on a clean shutdown.
//
// The publish leg needs no shutdown flush: Publish is synchronous and returns nil
// only after the ingest's WAL fsync (a 200), so there is never a buffered central
// event to drain here. Only the local durable sink carries a shutdown obligation,
// and only if it is a Closer (the FileSink is; a stateless test sink is not).
func (w *FanInWriter) Close() error {
	if c, ok := w.local.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// toPublishWire maps a locally-chained ChainEnvelope onto the pre-chain wire
// envelope. It KEEPS Sequence (the ingest's 409 authority), projects the OCU
// mandatory audit fields out of the canonical OCSF Event (which buildEvent
// populated injectively from the audit.Record), and carries the Event as the
// payload. It DROPS Source, PriorHash, and Hash: the ingest derives source from
// the verified client-cert CN (INV-1) and authors its own chain (INV-3).
//
// The projection reads the OCSF positions buildEvent writes: actor.user.name is
// the host-attested caller (actor_id, NFR-SEC-09), actor.session.uid is the
// reservation key (session_id and resource), metadata.unmapped.action is the
// privileged action, status is the outcome, and metadata.correlation_uid is the
// cross-surface correlation id (trace_id). A malformed Event that does not parse
// yields a wire with the sequence and payload set and empty header fields; the
// server's validate() then 400s it (bounds), which is the fail-closed outcome --
// never a silent partial accept.
//
// OWNER-GATED SEAM: trace_id here is metadata.correlation_uid. If the deployment
// requires a distinct request-scoped trace id (not the OCSF correlation_uid),
// ChainSink must thread it and this projection reads it from a widened
// ChainEnvelope instead -- a control-side decision at the injection layer.
func toPublishWire(env ChainEnvelope) PublishWire {
	w := PublishWire{Sequence: env.Sequence, Payload: env.Event}
	var e struct {
		ActivityName string `json:"activity_name"`
		Status       string `json:"status"`
		Actor        struct {
			User struct {
				Name string `json:"name"`
			} `json:"user"`
			Session struct {
				UID string `json:"uid"`
			} `json:"session"`
		} `json:"actor"`
		Metadata struct {
			CorrelationUID string `json:"correlation_uid"`
			Unmapped       struct {
				Action string `json:"action"`
			} `json:"unmapped"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(env.Event, &e); err != nil {
		return w // header fields empty -> server validate() 400s -> fail-closed
	}
	w.TraceID = e.Metadata.CorrelationUID
	w.SessionID = e.Actor.Session.UID
	w.ActorID = e.Actor.User.Name
	w.Resource = e.Actor.Session.UID
	w.Action = firstNonEmpty(e.Metadata.Unmapped.Action, e.ActivityName)
	w.Outcome = e.Status
	return w
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// interface assertion aid: any Publisher whose Publish maps a non-200 to a
// non-nil error preserves fail-closed. audit.ErrAuditWriteFailed is referenced
// so the package dependency is explicit for readers wiring the caller side.
var _ = audit.ErrAuditWriteFailed
