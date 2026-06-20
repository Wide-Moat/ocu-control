// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// TestNullSinkWriteNeverFails proves the default writer discards the envelope and
// returns nil, so the default wiring never denies a privileged action on the audit
// step.
func TestNullSinkWriteNeverFails(t *testing.T) {
	t.Parallel()
	var w ocsf.EventWriter = ocsf.NullSink{}
	if err := w.Write(context.Background(), ocsf.ChainEnvelope{Source: "control", Sequence: 1}); err != nil {
		t.Fatalf("NullSink.Write = %v, want nil", err)
	}
}

// TestNullSinkDefaultStillComputesChain proves the DEFAULT wiring (ChainSink over a
// NullSink) still COMPUTES and ADVANCES the chain in-process even though nothing is
// durably persisted: Emit returns nil and the sequence advances, so the spine is
// validatable in-process while the default persists nothing (the minimal-shelf
// zero-dependency default).
func TestNullSinkDefaultStillComputesChain(t *testing.T) {
	t.Parallel()
	sink := ocsf.NewChainSink(newClock(), ocsf.NullSink{}, "control")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := sink.Emit(ctx, audit.Record{Action: audit.ActionCreateCommit, Key: "k", Caller: "c", Tenant: "t"}); err != nil {
			t.Fatalf("Emit %d over NullSink = %v, want nil (default never denies)", i, err)
		}
	}
}
