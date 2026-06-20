// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import "context"

// EventWriter is the durable-emit seam BEHIND the chain sink: it receives the full
// ChainEnvelope (the canonical OCSF payload plus the out-of-band sequence and chain
// link) and makes it durable, returning nil ONLY on success. A non-nil Write denies
// the privileged action that triggered it (the sink wraps it as ErrAuditWriteFailed,
// and the caller's fail-closed branch treats that as a hard deny). This is the SINGLE
// seam a deployment fills with a real durable target — a file appender, a WORM/bus
// client, a SIEM forwarder — with NO change to the AuditSink interface or any Emit
// call site. Control owns the SOURCE side (serialize + chain + emit to one writer);
// the bus, WORM store, SIEM, transparency log, and the daily Merkle-head submission
// are all downstream of this writer, not Control's to own.
type EventWriter interface {
	// Write makes env durable and returns nil, or returns a non-nil error the chain
	// sink wraps as ErrAuditWriteFailed. It MUST NOT report success for an envelope
	// it did not durably write.
	Write(ctx context.Context, env ChainEnvelope) error
}

// NullSink is the DEFAULT EventWriter: it discards the envelope and returns nil. With
// it wired, the chain is still COMPUTED and VALIDATABLE in-process (each Emit advances
// the sequence and links the prior hash), but nothing is durably persisted — the
// zero-external-dependency minimal-shelf default. A real EventWriter slots in behind
// this same interface with no call-site change; only the NewChainSink writer argument
// changes at the daemon composition root. NullSink holds no state and is safe for
// concurrent use.
type NullSink struct{}

// Write discards env and returns nil. It never persists and never fails, so the
// default wiring never denies a privileged action on the audit step while still
// exercising the full serialize-and-chain path.
func (NullSink) Write(_ context.Context, _ ChainEnvelope) error { return nil }

// Compile-time proof NullSink satisfies the EventWriter seam.
var _ EventWriter = NullSink{}
