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

// sampleChainEnvelope carries an OCSF event shaped as buildEvent produces it,
// so the mandatory-field projection has real nested values to extract.
func sampleChainEnvelope() ChainEnvelope {
	event := `{
		"class_uid": 6003,
		"activity_name": "session.create",
		"status": "success",
		"actor": {
			"user": {"name": "caller-principal", "uid_alt": "tenant-x"},
			"session": {"uid": "resv-key-1"},
			"invoked_by": "gateway"
		},
		"metadata": {
			"correlation_uid": "trace-corr-1",
			"unmapped": {"action": "session_create"}
		}
	}`
	return ChainEnvelope{
		Source:    "control",
		Sequence:  7,
		PriorHash: "deadbeef",
		Hash:      "cafef00d",
		Event:     json.RawMessage(event),
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
	if string(wire.Payload) != string(env.Event) {
		t.Fatalf("publish wire Payload must be the canonical event bytes verbatim")
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
	// All OCU mandatory audit fields (NFR-MAINT-AUDIT-SCHEMA) present as
	// discrete top-level keys.
	for _, want := range []string{"trace_id", "session_id", "actor_id", "resource", "action", "outcome", "sequence", "payload"} {
		if _, ok := keyed[want]; !ok {
			t.Fatalf("publish wire missing required mandatory field %q", want)
		}
	}
}

// The mandatory-field projection reads the OCSF positions buildEvent writes:
// actor.user.name -> actor_id, actor.session.uid -> session_id/resource,
// metadata.unmapped.action -> action, status -> outcome,
// metadata.correlation_uid -> trace_id. A wrong mapping (e.g. trace_id lost)
// would break SIEM correlation, so pin each one.
func TestFanInProjectsMandatoryFieldsFromOCSF(t *testing.T) {
	lw := &recordingWriter{}
	pub := &recordingPublisher{}
	w, _ := NewFanInWriter(lw, pub)
	if err := w.Write(context.Background(), sampleChainEnvelope()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	wire := pub.got[0]
	cases := map[string]string{
		"trace_id":   "trace-corr-1",
		"session_id": "resv-key-1",
		"actor_id":   "caller-principal",
		"resource":   "resv-key-1",
		"action":     "session_create",
		"outcome":    "success",
	}
	got := map[string]string{
		"trace_id": wire.TraceID, "session_id": wire.SessionID, "actor_id": wire.ActorID,
		"resource": wire.Resource, "action": wire.Action, "outcome": wire.Outcome,
	}
	for field, want := range cases {
		if got[field] != want {
			t.Fatalf("projected %s = %q, want %q", field, got[field], want)
		}
	}
}

// A malformed OCSF event does not crash the projection: the wire keeps sequence
// and payload with empty header fields, and the server's validate() then 400s
// it (fail-closed), never a silent partial accept.
func TestFanInProjectionToleratesMalformedEvent(t *testing.T) {
	lw := &recordingWriter{}
	pub := &recordingPublisher{}
	w, _ := NewFanInWriter(lw, pub)
	env := sampleChainEnvelope()
	env.Event = json.RawMessage(`{not-json`)
	if err := w.Write(context.Background(), env); err != nil {
		t.Fatalf("Write must not crash on a malformed event, got %v", err)
	}
	wire := pub.got[0]
	if wire.Sequence != env.Sequence || wire.ActorID != "" {
		t.Fatalf("malformed event: want seq kept + empty header, got seq=%d actor_id=%q", wire.Sequence, wire.ActorID)
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

// closingRecordingWriter is a local EventWriter that also records whether Close
// ran and can return a Close error. It is an io.Closer, so the composite must
// forward Close to it (the FileSink is a Closer in production).
type closingRecordingWriter struct {
	recordingWriter
	closed   bool
	closeErr error
}

func (w *closingRecordingWriter) Close() error {
	w.closed = true
	return w.closeErr
}

// The composite must be a drop-in for the bare FileSink at the daemon's
// auditWriter seam (EventWriter + Close). Close forwards to the local durable
// sink's Close so the shutdown fsync still runs when the fan-in replaces the
// FileSink; the synchronous publish leg carries no shutdown obligation.
func TestFanInCloseForwardsToLocalSink(t *testing.T) {
	lw := &closingRecordingWriter{}
	w, err := NewFanInWriter(lw, &recordingPublisher{})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !lw.closed {
		t.Fatal("Close must forward to the local durable sink (the shutdown fsync); local Close was NOT called")
	}
}

// A Close error from the local sink propagates: a failed shutdown fsync must not
// be swallowed.
func TestFanInCloseSurfacesLocalCloseError(t *testing.T) {
	sentinel := errors.New("local close boom")
	lw := &closingRecordingWriter{closeErr: sentinel}
	w, _ := NewFanInWriter(lw, &recordingPublisher{})
	if err := w.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close must surface the local sink's close error, got %v", err)
	}
}

// A local sink that is NOT a Closer (a stateless test sink) makes Close a safe
// no-op -- never a panic, never an error.
func TestFanInCloseIsNoOpWhenLocalIsNotACloser(t *testing.T) {
	w, _ := NewFanInWriter(&recordingWriter{}, &recordingPublisher{})
	if err := w.Close(); err != nil {
		t.Fatalf("Close on a non-Closer local must be a nil-error no-op, got %v", err)
	}
}
