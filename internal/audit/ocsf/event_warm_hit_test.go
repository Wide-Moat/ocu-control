// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// TestUnmappedWarmHitOmittedIsByteIdentical proves a COLD create-commit (the
// common case) carries no warm_hit key: the omitempty tag keeps its canonical
// payload — and therefore its chain hash — byte-identical to before the field
// existed, so adding warm-pool audit did not re-key every pre-existing create.
func TestUnmappedWarmHitOmittedIsByteIdentical(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionCreateCommit, Channel: "operator", Key: "k"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(w.envs) != 1 {
		t.Fatalf("want 1 envelope, got %d", len(w.envs))
	}
	if bytesContain(w.envs[0].Event, `"warm_hit"`) {
		t.Errorf("a cold create-commit carries a warm_hit key; omitempty must omit it so the hash is byte-identical to before the field existed. Event: %s", w.envs[0].Event)
	}
}

// TestUnmappedWarmHitPresentWhenClaimed proves a warm-pool-served create-commit
// carries warm_hit=true in metadata.unmapped — the NFR-SEC-72 pool-claim
// transition is recorded on the tamper-evident spine, distinguishable from a cold
// materialize.
func TestUnmappedWarmHitPresentWhenClaimed(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	if err := sink.Emit(context.Background(), audit.Record{
		Action:  audit.ActionCreateCommit,
		Channel: "operator",
		Key:     "sess-warm",
		WarmHit: true,
	}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(w.envs) != 1 {
		t.Fatalf("want 1 envelope, got %d", len(w.envs))
	}
	if !bytesContain(w.envs[0].Event, `"warm_hit":true`) {
		t.Errorf("a warm-pool create-commit did not serialize warm_hit into unmapped; the pool-claim transition would be indistinguishable from a cold materialize on the spine. Event: %s", w.envs[0].Event)
	}
}
