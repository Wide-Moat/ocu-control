// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// recordingWriter is a local EventWriter stub: it records the envelopes it was
// asked to write and can be told to fail.
type recordingWriter struct {
	got     []ChainEnvelope
	failErr error
}

func (w *recordingWriter) Write(_ context.Context, env ChainEnvelope) error {
	if w.failErr != nil {
		return w.failErr
	}
	w.got = append(w.got, env)
	return nil
}

// recordingPublisher is a central Publisher stub.
type recordingPublisher struct {
	got     []PublishWire
	failErr error
}

func (p *recordingPublisher) Publish(_ context.Context, wire PublishWire) error {
	if p.failErr != nil {
		return p.failErr
	}
	p.got = append(p.got, wire)
	return nil
}

func sampleChainEnvelope() ChainEnvelope {
	return ChainEnvelope{
		Source:    "control",
		Sequence:  7,
		PriorHash: "deadbeef",
		Hash:      "cafef00d",
		Event:     json.RawMessage(`{"class_uid":6003,"activity_name":"session.create"}`),
	}
}

// The happy path: both legs receive the event and Write returns nil (the ack).
func TestFanInWriteTeesToBothLegs(t *testing.T) {
	lw := &recordingWriter{}
	pub := &recordingPublisher{}
	w, err := NewFanInWriter(lw, pub)
	if err != nil {
		t.Fatalf("NewFanInWriter: %v", err)
	}
	env := sampleChainEnvelope()
	if err := w.Write(context.Background(), env); err != nil {
		t.Fatalf("Write must be nil when both legs succeed, got %v", err)
	}
	if len(lw.got) != 1 {
		t.Fatalf("local leg got %d writes, want 1", len(lw.got))
	}
	if len(pub.got) != 1 {
		t.Fatalf("publish leg got %d publishes, want 1", len(pub.got))
	}
}

// The publish wire keeps sequence + event and DROPS source/prior_hash/hash.
// A leaked chain field would be a 400 at the ingest and an INV-1/INV-3
// violation; the mapper must never carry them. PublishWire has no such field,
// so we assert the marshaled body's keys directly.
func TestFanInPublishWireStripsChainFields(t *testing.T) {
	lw := &recordingWriter{}
	pub := &recordingPublisher{}
	w, _ := NewFanInWriter(lw, pub)
	env := sampleChainEnvelope()
	if err := w.Write(context.Background(), env); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wire := pub.got[0]
	if wire.Sequence != env.Sequence {
		t.Fatalf("publish wire Sequence = %d, want %d (the ingest 409 authority)", wire.Sequence, env.Sequence)
	}
	if string(wire.Event) != string(env.Event) {
		t.Fatalf("publish wire Event must be the canonical bytes verbatim")
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal wire: %v", err)
	}
	var keyed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keyed); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}
	for _, forbidden := range []string{"source", "prior_hash", "hash", "chain_hash"} {
		if _, ok := keyed[forbidden]; ok {
			t.Fatalf("publish wire carries forbidden pipeline-authored key %q (INV-1/INV-3)", forbidden)
		}
	}
	for _, want := range []string{"sequence", "event"} {
		if _, ok := keyed[want]; !ok {
			t.Fatalf("publish wire missing required field %q", want)
		}
	}
}

// Fail-closed on the PUBLISH leg: a publish failure fails the whole Write, so
// ChainSink does not advance and the caller denies the action. This is the
// anti-fake-green core -- a composite that swallowed a publish failure would let
// a source ack without a central commit (the exact gate-#3 hole).
func TestFanInFailsClosedOnPublishError(t *testing.T) {
	lw := &recordingWriter{}
	pub := &recordingPublisher{failErr: errors.New("ingest 503")}
	w, _ := NewFanInWriter(lw, pub)
	err := w.Write(context.Background(), sampleChainEnvelope())
	if err == nil {
		t.Fatal("Write must fail closed when the publish leg fails, got nil")
	}
}

// Fail-closed on the LOCAL leg, and the publish leg is NOT reached (local-first
// ordering): there is no committed local record to reconcile a publish against.
func TestFanInFailsClosedOnLocalErrorAndSkipsPublish(t *testing.T) {
	lw := &recordingWriter{failErr: errors.New("disk full")}
	pub := &recordingPublisher{}
	w, _ := NewFanInWriter(lw, pub)
	err := w.Write(context.Background(), sampleChainEnvelope())
	if err == nil {
		t.Fatal("Write must fail closed when the local leg fails, got nil")
	}
	if len(pub.got) != 0 {
		t.Fatalf("publish leg must NOT run when the local write failed, got %d publishes", len(pub.got))
	}
}

// New rejects a nil leg at construction: a source with no publish leg silently
// regressing to the forensic-only mirror is the exact bug this fan-in fixes.
func TestNewFanInWriterRejectsNilLegs(t *testing.T) {
	if _, err := NewFanInWriter(nil, &recordingPublisher{}); err == nil {
		t.Fatal("nil local writer must be rejected")
	}
	if _, err := NewFanInWriter(&recordingWriter{}, nil); err == nil {
		t.Fatal("nil publisher must be rejected")
	}
}
