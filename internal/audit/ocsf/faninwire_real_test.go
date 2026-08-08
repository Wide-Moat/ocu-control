// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// capturingWriter keeps the last envelope the sink emitted.
type capturingWriter struct{ last ChainEnvelope }

func (c *capturingWriter) Write(_ context.Context, env ChainEnvelope) error {
	c.last = env
	return nil
}

// TestToPublishWireOverRealEnvelopes drives the projection with envelopes built by
// the PRODUCTION path -- a real ChainSink over a real audit.Record -- instead of a
// hand-written fixture.
//
// That distinction is the whole test. The existing fixture hardcodes
// `"status": "success"` while buildEvent actually emits "Success", and the
// difference of one letter is the difference between a working central audit leg
// and a daemon that denies every privileged action: an out-of-enum outcome is
// refused by the publish leg, a refused publish fails the write closed, and a
// failed audit write denies the action. The DENY-ALL case is worse still, because
// the action it would block is the kill-switch.
func TestToPublishWireOverRealEnvelopes(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC))

	for _, tc := range []struct {
		name        string
		rec         audit.Record
		wantScope   string
		wantOutcome string
	}{
		{
			name:        "per-session action carries its key",
			rec:         audit.Record{Action: audit.ActionCreateCommit, Channel: "gateway", Key: "tenant/sess-1", Caller: "svc", Tenant: "t"},
			wantScope:   "tenant/sess-1",
			wantOutcome: "success",
		},
		{
			// audit.Record documents Key as empty for a DENY-ALL revoke.
			name:        "deployment-wide revoke has no key and must still be publishable",
			rec:         audit.Record{Action: audit.ActionRevokeAll, Channel: "operator", Key: "", Caller: "operator@example", Tenant: "t"},
			wantScope:   globalScope,
			wantOutcome: "success",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &capturingWriter{}
			if err := NewChainSink(clk, w, "control").Emit(context.Background(), tc.rec); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			wire := toPublishWire(w.last)

			if wire.Outcome != tc.wantOutcome {
				t.Errorf("outcome = %q, want %q (the contract pins success|failure|unknown; the OCSF label is capitalised)", wire.Outcome, tc.wantOutcome)
			}
			if wire.SessionID != tc.wantScope || wire.Resource != tc.wantScope {
				t.Errorf("session_id/resource = %q/%q, want %q", wire.SessionID, wire.Resource, tc.wantScope)
			}
			// Every field the contract marks required must be non-empty, or the
			// publish leg refuses the record and the action is denied.
			for _, f := range []struct{ name, value string }{
				{"trace_id", wire.TraceID},
				{"session_id", wire.SessionID},
				{"actor_id", wire.ActorID},
				{"resource", wire.Resource},
				{"action", wire.Action},
			} {
				if f.value == "" {
					t.Errorf("mandatory field %s is empty; the publish leg would refuse this record and deny the action", f.name)
				}
			}
		})
	}
}
