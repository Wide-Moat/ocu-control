// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// selfConsistentEnvelope builds a ChainEnvelope whose Hash is correctly computed over
// (priorHash, sequence, event) — so ValidateChain's hash recompute passes and only the
// re-anchor rule (or its marker) governs acceptance. It is white-box because it calls
// the unexported computeHash, isolating PIN (iii) to the anchor check rather than a
// hash mismatch.
func selfConsistentEnvelope(t *testing.T, seq uint64, priorHash string, event []byte) ChainEnvelope {
	t.Helper()
	hash, err := computeHash(priorHash, seq, event)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	return ChainEnvelope{Source: "control", Sequence: seq, PriorHash: priorHash, Hash: hash, Event: event}
}

// TestValidateChainRejectsSilentReAnchor is PIN (iii), the core tamper-evidence
// property. A mid-file record that re-anchors the spine at genesis WITHOUT a
// chain-break marker — a silent restart or a spliced fresh segment — must be REJECTED.
// This is exactly the pre-fix behaviour (a fresh ChainSink re-anchored at genesis on
// every restart); the marker rule makes the silent re-anchor detectable.
//
// Two-sided: the SAME re-anchoring record WITH a chain-break marker is ACCEPTED, so the
// rejection is the missing marker, not the genesis anchor itself.
func TestValidateChainRejectsSilentReAnchor(t *testing.T) {
	t.Parallel()

	// A normal genesis-anchored first event (sequence 1).
	normalEvent, err := canonicalize(buildEvent(state.NewFakeClock(fixedStart), auditRecordForTest()))
	if err != nil {
		t.Fatalf("canonicalize normal: %v", err)
	}
	first := selfConsistentEnvelope(t, 1, genesisPriorHash, normalEvent)

	// A SECOND record (sequence 2) that re-anchors at genesis with a NORMAL event — the
	// silent re-anchor. Sequence stays monotonic (2 = 1+1); only the anchor is wrong.
	silent := selfConsistentEnvelope(t, 2, genesisPriorHash, normalEvent)

	err = ValidateChain([]ChainEnvelope{first, silent})
	if err == nil {
		t.Fatal("ValidateChain ACCEPTED a mid-file genesis re-anchor with no chain-break marker; a silent re-anchor must be rejected as tamper")
	}
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("error = %v, want ErrChainInvalid", err)
	}

	// Two-sided complement: the SAME re-anchor, but the record is a chain-break marker
	// with a non-empty observed_prior_tip — now ACCEPTED.
	markerEvent, err := canonicalize(buildChainBreakEvent(state.NewFakeClock(fixedStart), "deadbeef"))
	if err != nil {
		t.Fatalf("canonicalize marker: %v", err)
	}
	marker := selfConsistentEnvelope(t, 2, genesisPriorHash, markerEvent)
	if err := ValidateChain([]ChainEnvelope{first, marker}); err != nil {
		t.Fatalf("ValidateChain rejected a re-anchor WITH a chain-break marker: %v; the marker must make the re-anchor legitimate", err)
	}
}

// TestValidateChainRejectsChainBreakWithEmptyObservedTip is PIN (ii): a chain-break
// marker whose observed_prior_tip is empty is rejected — the discontinuity must record
// the observed tail state (a recovered hash or the "unreadable" sentinel). This guards
// against a marker that claims a break but documents nothing.
func TestValidateChainRejectsChainBreakWithEmptyObservedTip(t *testing.T) {
	t.Parallel()

	normalEvent, err := canonicalize(buildEvent(state.NewFakeClock(fixedStart), auditRecordForTest()))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	first := selfConsistentEnvelope(t, 1, genesisPriorHash, normalEvent)

	// Hand-build a marker event with an EMPTY observed_prior_tip (bypassing the
	// constructor's coercion) to prove ValidateChain independently enforces the invariant.
	emptyMarker := OCSFEvent{
		ClassUID:    classUIDAPIActivity,
		CategoryUID: categoryUIDApplicationActivity,
		ChainBreak:  &ChainBreakInfo{ObservedPriorTip: ""},
	}
	emptyMarkerBytes, err := json.Marshal(emptyMarker)
	if err != nil {
		t.Fatalf("marshal empty marker: %v", err)
	}
	env := selfConsistentEnvelope(t, 2, genesisPriorHash, emptyMarkerBytes)

	err = ValidateChain([]ChainEnvelope{first, env})
	if err == nil {
		t.Fatal("ValidateChain ACCEPTED a chain-break marker with an empty observed_prior_tip; the discontinuity must record the observed tail state")
	}
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("error = %v, want ErrChainInvalid", err)
	}
}

// auditRecordForTest is a minimal privileged record for building a normal event in the
// white-box chain tests.
func auditRecordForTest() audit.Record {
	return audit.Record{Action: audit.ActionRevokeOne, Channel: "operator", Key: "k", Reason: "r"}
}
