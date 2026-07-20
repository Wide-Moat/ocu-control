// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
// (ocu-audit docs/wire-surface.md). It carries the per-source Sequence (the
// ingest 409s a non-increasing value) and the canonical OCSF Event bytes, and
// deliberately no source/prior_hash/chain_hash. An adapter in the wiring layer
// converts this to the ocu-audit client's Envelope type; keeping our own struct
// keeps this package free of an ocu-audit import.
type PublishWire struct {
	Sequence uint64          `json:"sequence"`
	Event    json.RawMessage `json:"event"`
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

// toPublishWire maps a locally-chained ChainEnvelope onto the pre-chain wire
// envelope. It KEEPS Sequence (the ingest's 409 authority) and Event (the
// canonical bytes the pipeline will re-chain and hash), and DROPS Source,
// PriorHash, and Hash: the ingest derives source from the verified client-cert
// CN (INV-1) and authors its own chain (INV-3). A source that smuggled any of
// those would get a 400; this mapper structurally cannot, since PublishWire has
// no such field.
func toPublishWire(env ChainEnvelope) PublishWire {
	return PublishWire{
		Sequence: env.Sequence,
		Event:    env.Event,
	}
}

// interface assertion aid: any Publisher whose Publish maps a non-200 to a
// non-nil error preserves fail-closed. audit.ErrAuditWriteFailed is referenced
// so the package dependency is explicit for readers wiring the caller side.
var _ = audit.ErrAuditWriteFailed
