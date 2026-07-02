// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// collectingWriter records every ChainEnvelope written, so a test can inspect the
// spine a sink produced without a file.
type collectingWriter struct{ envs []ocsf.ChainEnvelope }

func (w *collectingWriter) Write(_ context.Context, env ocsf.ChainEnvelope) error {
	w.envs = append(w.envs, env)
	return nil
}

// TestNormalEventByteIdenticalWithChainBreakField is PIN (i): a normal
// privileged-action event, now that OCSFEvent carries the omitempty ChainBreak
// pointer, must serialize BYTE-FOR-BYTE as it did before the field existed — the nil
// pointer omits entirely. This guards the hash: if a refactor dropped omitempty (so
// the field rendered as "chain_break":null), every normal event's canonical bytes —
// and thus its hash and the whole downstream spine — would change. The guard is the
// byte-level assertion that the marshalled normal event contains no chain_break key.
func TestNormalEventByteIdenticalWithChainBreakField(t *testing.T) {
	t.Parallel()
	// Emit a normal event through the real sink and capture its canonical bytes.
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")
	if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k", Reason: "r"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(w.envs) != 1 {
		t.Fatalf("want 1 envelope, got %d", len(w.envs))
	}
	// The canonical event bytes must not contain the chain_break key at all — the
	// omitempty nil pointer omits it, so the payload is identical to the pre-field shape.
	if bytesContain(w.envs[0].Event, `"chain_break"`) {
		t.Errorf("a normal event's canonical bytes contain a chain_break key; the omitempty pointer must omit it entirely so the hash is byte-identical to before the field existed. Event: %s", w.envs[0].Event)
	}
}

// TestChainBreakMarkerReAnchorsAndValidates proves a chain-break marker written
// mid-spine re-anchors at genesis, carries a non-empty observed_prior_tip, and the
// whole spine (normal events, then a marker, then more normal events) passes
// ValidateChain — the marked re-anchor is legitimate.
func TestChainBreakMarkerReAnchorsAndValidates(t *testing.T) {
	t.Parallel()
	w := &collectingWriter{}
	sink := ocsf.NewChainSink(newClock(), w, "control")

	// Two normal events (sequences 1, 2).
	for i := 0; i < 2; i++ {
		if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k"}); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	// A chain-break marker (sequence 3, re-anchored at genesis).
	if err := sink.EmitChainBreak(context.Background(), "deadbeefcafe"); err != nil {
		t.Fatalf("EmitChainBreak: %v", err)
	}
	// One more normal event (sequence 4, linking to the marker's hash).
	if err := sink.Emit(context.Background(), audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k"}); err != nil {
		t.Fatalf("post-marker emit: %v", err)
	}

	marker := w.envs[2]
	if marker.PriorHash != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("chain-break marker prior_hash = %q, want genesis (a marker re-anchors)", marker.PriorHash)
	}
	if err := ocsf.ValidateChain(w.envs); err != nil {
		t.Fatalf("ValidateChain rejected a spine with a legitimate chain-break marker: %v", err)
	}
}

// bytesContain reports whether b contains sub.
func bytesContain(b json.RawMessage, sub string) bool {
	return len(b) >= len(sub) && indexOf(string(b), sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
