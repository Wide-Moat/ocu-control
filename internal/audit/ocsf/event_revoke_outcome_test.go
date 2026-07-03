// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// TestUnmappedRevokeOutcomeOmittedIsByteIdentical guards the hash: a record that
// carries NO revoke outcome (every event that is not a destroy-with-outcome — a
// create, a revoke-one, a quota override, and a plain destroy) must serialize
// BYTE-FOR-BYTE as it did before Unmapped grew the revoke_outcome field. The
// omitempty tag omits the key entirely when the value is empty; if a refactor
// dropped omitempty (rendering "revoke_outcome":""), every such event's canonical
// bytes — and thus its hash and the whole downstream spine — would change. The
// guard is the byte-level assertion that a no-outcome event's canonical bytes carry
// no revoke_outcome key at all.
func TestUnmappedRevokeOutcomeOmittedIsByteIdentical(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	// A plain destroy with no recorded outcome — the common case before the
	// teardown auditor records one — must omit the key.
	if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionDestroy, Channel: "operator", Key: "k"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(w.envs) != 1 {
		t.Fatalf("want 1 envelope, got %d", len(w.envs))
	}
	if bytesContain(w.envs[0].Event, `"revoke_outcome"`) {
		t.Errorf("an event with no revoke outcome carries a revoke_outcome key; the omitempty tag must omit it entirely so the hash is byte-identical to before the field existed. Event: %s", w.envs[0].Event)
	}
}

// TestUnmappedRevokeOutcomePresentWhenRecorded proves the positive half: a destroy
// record that DOES carry a revoke outcome serializes it into
// metadata.unmapped.revoke_outcome verbatim. This is the load-bearing assertion for
// the teardown evidence — the outcome the finalizer observed must reach the
// tamper-evident spine, not be dropped by the serializer.
func TestUnmappedRevokeOutcomePresentWhenRecorded(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	if err := sink.Emit(context.Background(), audit.Record{
		Action:        audit.ActionDestroy,
		Channel:       "operator",
		Key:           "fs-42",
		RevokeOutcome: "marked_dead",
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(w.envs) != 1 {
		t.Fatalf("want 1 envelope, got %d", len(w.envs))
	}
	if !bytesContain(w.envs[0].Event, `"revoke_outcome":"marked_dead"`) {
		t.Errorf("a destroy record carrying RevokeOutcome=marked_dead did not serialize revoke_outcome into unmapped; the evidence would be lost from the spine. Event: %s", w.envs[0].Event)
	}
}
