// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlrpc_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/controlrpc"
)

// TestReplyMarshalRejectsAmbiguousVariant covers the fail-closed MarshalJSON guards
// on Reply: a Reply carrying NEITHER variant and a Reply carrying BOTH are each a
// protocol error, so the host never emits a tagless or multi-tag reply frame.
func TestReplyMarshalRejectsAmbiguousVariant(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rep  controlrpc.Reply
	}{
		{"neither variant", controlrpc.Reply{}},
		{"both variants", controlrpc.Reply{
			Accepted: &controlrpc.ShutdownAccepted{},
			Error:    &controlrpc.ControlError{BoundedReason: controlrpc.BoundedReason{ReasonCode: "OK"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.rep.MarshalJSON(); !errors.Is(err, controlrpc.ErrProtocol) {
				t.Fatalf("Reply.MarshalJSON(%s) = %v, want ErrProtocol", tc.name, err)
			}
		})
	}
}

// TestRequestMarshalRejectsTaglessFrame covers the fail-closed MarshalJSON guard on
// Request: a Request with no verb set is a protocol error, so the host never emits a
// tagless request frame.
func TestRequestMarshalRejectsTaglessFrame(t *testing.T) {
	t.Parallel()
	if _, err := (controlrpc.Request{}).MarshalJSON(); !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("empty Request.MarshalJSON() = %v, want ErrProtocol", err)
	}
}

// TestEncodeRejectsOversizeReply covers writeFrame's outbound bound reached through
// EncodeReply: a ControlError whose message overruns the frame cap is refused before
// any byte reaches the wire, so the host honors the symmetric frame bound.
func TestEncodeRejectsOversizeReply(t *testing.T) {
	t.Parallel()
	// A message far beyond the 64 KiB frame cap. It is built directly into the wire
	// struct so the encoder, not the bounded-reason decoder, is the path under test.
	huge := string(bytes.Repeat([]byte("A"), 70<<10))
	rep := controlrpc.Reply{Error: &controlrpc.ControlError{
		BoundedReason: controlrpc.BoundedReason{ReasonCode: "OK", Message: huge},
	}}
	var buf bytes.Buffer
	if err := controlrpc.EncodeReply(&buf, rep); !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("EncodeReply(oversize) = %v, want ErrProtocol", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("oversize reply wrote %d bytes; want 0 (refused before the wire)", buf.Len())
	}
}

// TestEncodeRejectsAmbiguousFrames covers the marshal-error propagation in
// EncodeRequest/EncodeReply: a tagless Request and an ambiguous Reply fail at the
// MarshalJSON step, so Encode surfaces ErrProtocol and writes nothing.
func TestEncodeRejectsAmbiguousFrames(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := controlrpc.EncodeRequest(&buf, controlrpc.Request{}); !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("EncodeRequest(empty) = %v, want ErrProtocol", err)
	}
	if err := controlrpc.EncodeReply(&buf, controlrpc.Reply{}); !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("EncodeReply(empty) = %v, want ErrProtocol", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("ambiguous encodes wrote %d bytes; want 0", buf.Len())
	}
}

// TestDecodeFrameBoundaryConditions covers readFrame's EOF discipline reached
// through DecodeRequest/DecodeReply: a clean EOF before any byte surfaces io.EOF (a
// closed peer), an unterminated non-empty frame at EOF is ErrProtocol (a peer that
// closed mid-frame), and a trailing-data frame after a complete object is
// ErrProtocol (two concatenated objects are not one frame).
func TestDecodeFrameBoundaryConditions(t *testing.T) {
	t.Parallel()

	// Clean EOF before any byte: a closed peer, surfaced as io.EOF so a caller can
	// distinguish it from a malformed frame.
	if _, err := controlrpc.DecodeRequest(bufio.NewReader(bytes.NewReader(nil))); !errors.Is(err, io.EOF) {
		t.Fatalf("DecodeRequest(empty stream) = %v, want io.EOF", err)
	}

	// A non-empty frame with no terminating newline at EOF: fail closed rather than
	// accept a possibly-truncated body.
	if _, err := controlrpc.DecodeRequest(bufio.NewReader(bytes.NewReader([]byte(`{"Shutdown":{}}`)))); !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("DecodeRequest(unterminated) = %v, want ErrProtocol", err)
	}

	// Trailing data after a complete object on one frame line: two concatenated
	// objects are not a single frame.
	twoObjs := []byte(`{"Shutdown":{}}{"Shutdown":{}}` + "\n")
	if _, err := controlrpc.DecodeRequest(bufio.NewReader(bytes.NewReader(twoObjs))); !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("DecodeRequest(trailing data) = %v, want ErrProtocol", err)
	}
}

// TestValidReasonCodeBoundaries covers the reason_code validator's reject branches
// reached through DecodeReply: a too-short code, a too-long code, a lowercase
// leading character, and a disallowed tail character each fail the bounded shape, so
// a guest cannot smuggle an off-pattern reason past the host decoder.
func TestValidReasonCodeBoundaries(t *testing.T) {
	t.Parallel()
	long := string(bytes.Repeat([]byte("A"), 65)) // 65 > 64 max
	cases := []struct {
		name string
		code string
	}{
		{"too short", "A"},
		{"too long", long},
		{"lowercase lead", "aBC"},
		{"bad tail char", "A-B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := []byte(`{"ControlError":{"reason_code":"` + tc.code + `"}}` + "\n")
			_, err := controlrpc.DecodeReply(bufio.NewReader(bytes.NewReader(frame)))
			if !errors.Is(err, controlrpc.ErrProtocol) {
				t.Fatalf("DecodeReply(reason_code=%q) = %v, want ErrProtocol", tc.code, err)
			}
		})
	}
}

// TestDialConnectRefusedIsNonAuthoritative covers Shutdown's transport-drop branch:
// the sock dir passes the 0700 host-owned gate but carries NO listening socket, so
// connect(2) is refused. The dial returns a wrapped error (diagnostic, never nil)
// but the branch is reached AFTER the gate, proving the advisory dial fails
// gracefully when the guest endpoint is absent.
func TestDialConnectRefusedIsNonAuthoritative(t *testing.T) {
	skipIfNoUDS(t)
	dir := hostOwnedSockDir(t) // 0700 host-owned, but no socket bound inside
	_ = filepath.Join(dir, "control.sock")

	d := newTestDialer(t, time.Second)
	err := d.Shutdown(context.Background(), dir, "ocu-sess-abc")
	if err == nil {
		t.Fatal("dial to an empty 0700 dir returned nil; want a transport error")
	}
	// It is NOT a gate refusal (the gate passed) and NOT a mint-identity error: it is
	// a real connect failure surfaced for diagnostics.
	if errors.Is(err, controlrpc.ErrSockDirGate) {
		t.Fatalf("connect-refused dial reported a gate error: %v", err)
	}
}

// TestNewDialerNonPositiveTimeoutStillBounds covers NewDialer's fallback for a
// non-positive timeout: the dialer must still bound its wait (the default deadline),
// so an advisory dial to an absent endpoint returns rather than hanging.
func TestNewDialerNonPositiveTimeoutStillBounds(t *testing.T) {
	skipIfNoUDS(t)
	dir := hostOwnedSockDir(t)
	// timeout 0 exercises the defaultDialTimeout fallback inside NewDialer.
	d := newTestDialer(t, 0)

	done := make(chan error, 1)
	go func() { done <- d.Shutdown(context.Background(), dir, "ocu-sess-abc") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("dial to an empty dir returned nil; want a bounded transport error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dial did not return within the bounded window; the timeout fallback did not engage")
	}
}
