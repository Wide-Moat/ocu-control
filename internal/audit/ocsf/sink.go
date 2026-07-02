// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"fmt"
	"sync"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// ChainSink is the real audit.AuditSink: it maps each privileged audit.Record onto a
// faithful-but-minimal OCSF event, assigns a per-source MONOTONIC sequence, links the
// prior event's hash into a tamper-evident spine, and writes the resulting
// ChainEnvelope to a single EventWriter — all on the success path, BEFORE the caller
// acknowledges the privileged action. A write failure is wrapped as
// audit.ErrAuditWriteFailed, which the caller's existing fail-closed branch treats as
// a hard deny.
//
// The sink is the SOURCE side only (ADR-0009: Control is a source on the host audit
// fan-in). It serializes, chains, and emits to ONE writer; it does NOT own the bus,
// WORM store, SIEM, transparency log, or the daily Merkle-head submission — those are
// the seams behind and downstream of the EventWriter. The per-source sequence is
// namespaced by the source string so a multi-source fan-in keeps per-source
// monotonicity without this source assuming a global order.
//
// It is safe for concurrent use: a mutex makes sequence assignment + prior-hash read
// atomic, so two concurrent privileged Emits receive strictly ordered sequence/links.
type ChainSink struct {
	clk    state.Clock
	writer EventWriter
	source string

	mu       sync.Mutex
	lastSeq  uint64 // last committed sequence; 0 before the first successful Emit
	priorTip string // hash of the last committed event; genesisPriorHash before any
}

// Compile-time proof ChainSink satisfies the audit.AuditSink seam the lifecycle and
// kill-switch layers hold — the real serializer slots in behind the frozen interface
// with no call-site change.
var _ audit.AuditSink = (*ChainSink)(nil)

// NewChainSink constructs a ChainSink over the injected Clock, the durable
// EventWriter, and the source name. The Clock supplies the OCSF event time only —
// never the ordering, which comes from the logical sequence. The default daemon
// wiring passes NullSink{} as the writer (compute-and-validate, persist-nothing) and
// "control" as the source; a real EventWriter slots in here with no other change.
// The genesis tip is the fixed all-zero prior-hash, so the first event links to a
// well-known recomputable anchor.
func NewChainSink(clk state.Clock, w EventWriter, source string) *ChainSink {
	return &ChainSink{
		clk:      clk,
		writer:   w,
		source:   source,
		priorTip: genesisPriorHash,
	}
}

// ResumeChainSink constructs a ChainSink that CONTINUES an existing per-source spine
// from tip, so a daemon restart keeps the sequence strictly monotonic and the
// prior-hash link unbroken across the boot boundary — the single continuous spine
// ADR-0009 and component-07 require (chain order derives from the per-source monotonic
// sequence; the chain has zero breaks). tip is read from the durable file by ReadTip;
// tip.Fresh true is the legitimate genesis start (empty/absent file), so this reduces
// to NewChainSink's initial state. The FIRST Emit after resume assigns tip.LastSeq+1
// and links to tip.PriorTip, exactly continuing the spine.
func ResumeChainSink(clk state.Clock, w EventWriter, source string, tip Tip) *ChainSink {
	return &ChainSink{
		clk:      clk,
		writer:   w,
		source:   source,
		lastSeq:  tip.LastSeq,
		priorTip: tip.PriorTip,
	}
}

// Emit maps rec onto an OCSF event, assigns the next sequence, computes the chain
// hash, and writes the ChainEnvelope. It returns nil ONLY when the writer durably
// accepted the envelope; on a writer failure it returns a wrapped
// audit.ErrAuditWriteFailed and does NOT advance the sequence or the prior-hash tip,
// so the FAILED action consumes no sequence number and the next action links cleanly
// (the failed action is denied by the caller's fail-closed branch). A cancelled
// context is itself a fail-closed deny before any work.
func (s *ChainSink) Emit(ctx context.Context, rec audit.Record) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: context: %w", audit.ErrAuditWriteFailed, err)
	}

	ev := buildEvent(s.clk, rec)
	eventBytes, err := canonicalize(ev)
	if err != nil {
		// A canonicalize failure is fail-closed: the action is denied and no sequence
		// is consumed. It cannot occur for the fixed OCSFEvent shape, but the branch is
		// real, not a panic.
		return fmt.Errorf("%w: %w", audit.ErrAuditWriteFailed, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sequence := s.lastSeq + 1
	priorHash := s.priorTip
	hash, err := computeHash(priorHash, sequence, eventBytes)
	if err != nil {
		return fmt.Errorf("%w: %w", audit.ErrAuditWriteFailed, err)
	}

	env := ChainEnvelope{
		Source:    s.source,
		Sequence:  sequence,
		PriorHash: priorHash,
		Hash:      hash,
		Event:     eventBytes,
	}
	if err := s.writer.Write(ctx, env); err != nil {
		// A durable write failure must NOT advance lastSeq/priorTip: the failed action
		// consumes no sequence and never poisons the chain, so a retried or next action
		// links cleanly. The caller's fail-closed branch denies the action.
		return fmt.Errorf("%w: %w", audit.ErrAuditWriteFailed, err)
	}

	// Commit only on a durable write: the spine advances atomically under the lock.
	s.lastSeq = sequence
	s.priorTip = hash
	return nil
}

// Source returns the source name this sink namespaces its sequence under. It is
// read-only diagnostic context (the per-source spine identity), never an authority
// subject.
func (s *ChainSink) Source() string { return s.source }
