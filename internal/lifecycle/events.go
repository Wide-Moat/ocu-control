// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle

import (
	"context"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// This file is the DESIGN-FENCED lifecycle event seam for the admin console's live
// view (ADR-0022, the GET /v1alpha/events SSE surface). It is a SEAM, not a full
// event-stream implementation: the SSE delta schema is unfrozen (ADR-0022 Open
// Question #2), so this round defines the typed publish port the Manager emits
// lifecycle transitions to and the subscribe shape an SSE handler will consume —
// exactly the same design-fenced discipline as the runtime EgressProgrammer /
// UnmountTrigger ports. The real fan-out (a buffered broadcast hub an SSE
// text/event-stream handler subscribes to) lands when the event schema is frozen.
// Until then a nil publisher leaves publishing a clean no-op (the nil-guard
// minimal-shelf default the runtime seams use), and the admin console polls the GET
// endpoints (list / get / deployment) for its live view.
//
// Why a SEPARATE seam, not the audit sink: the OCSF audit emit is write-only to a
// durable file (or null) — it is not a consumable in-process stream. The console's
// live view needs a fan-out a subscriber reads, so the lifecycle publishes its
// transitions to THIS port, independent of the audit chain. The two never couple:
// audit is the durable compliance record; this is the ephemeral live-view feed.

// LifecycleEvent is one live-view delta — intentionally THIN: the host-derived
// session key, the NEW state the row transitioned to, and the instant of the
// transition. It deliberately mirrors the SessionView projection (key + lowercase
// state + a timestamp) rather than modelling a fat event taxonomy: the SSE wire
// schema is unfrozen (ADR-0022 Open Question #2), so a thin delta the eventual SSE
// consumer and the lifecycle publisher can agree on is enough for the seam — richer
// fields are added when the schema freezes, not speculatively now. It carries NO
// credential and NO authority (the key is recorded data, never addressable
// authority — NFR-SEC-43). State reuses the canonical state.SessionState so the
// delta cannot drift from the lifecycle's own state set.
type LifecycleEvent struct {
	// Key is the host-derived session key the transition is about.
	Key string
	// State is the NEW lifecycle state the row reached (Reserved -> Active ->
	// Released). The SSE handler renders its lowercase name, the same casing the
	// SessionView read surface uses.
	State state.SessionState
	// At is the instant of the transition (from the injected clock).
	At time.Time
}

// EventPublisher is the NARROW design-fenced port the Manager publishes lifecycle
// transitions to for the live-view fan-out. It is satisfied later by a broadcast
// hub an SSE handler subscribes to; this round it is a typed seam with a nil-safe
// no-op default, so the publish call sites are in place and proven without the
// event schema being frozen (ADR-0022 Open Question #2). Publish is best-effort and
// non-fatal: a live-view feed is ephemeral, so a publish failure or a missing hub
// NEVER affects the create/destroy outcome — exactly like the metrics Recorder.
type EventPublisher interface {
	// Publish emits one lifecycle transition to the live-view fan-out. It must not
	// block the lifecycle path (a real hub buffers or drops, it never back-pressures
	// a create), and it never returns an error the caller acts on — the feed is
	// observational.
	Publish(ctx context.Context, ev LifecycleEvent)
}

// publishEvent is the Manager's guarded publish: a nil events port is a clean
// no-op, so the base pipeline runs without a fan-out hub wired. It is the single
// place the lifecycle reaches the event seam, keeping the publish discipline (never
// fatal, never blocking) in one spot. The transition instant is read from the
// injected clock so the delta carries the same time source the rest of the pipeline
// uses.
func (m *Manager) publishEvent(ctx context.Context, newState state.SessionState, key string) {
	if m.events == nil {
		return
	}
	m.events.Publish(ctx, LifecycleEvent{Key: key, State: newState, At: m.clk.Now()})
}
