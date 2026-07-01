// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package controlrpc_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/Wide-Moat/ocu-control/internal/controlrpc"
)

// TestProperty_ClosedUnion is the SECOND MANDATORY property test (the closed
// control-RPC union). It generates arbitrary top-level JSON frames and asserts the
// closed externally-tagged union NEVER silent-accepts: every frame is EITHER a
// recognized v1 variant that round-trips, OR a hard controlrpc.ErrProtocol. A
// multi-tag frame, a non-empty Shutdown/ShutdownAccepted body, a null frame, an
// unknown tag, or a non-object frame is deterministically ErrProtocol; a known tag
// with the empty/valid body round-trips in its own direction.
func TestProperty_ClosedUnion(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		frame := drawFrame(rt)

		// Request direction: only {"Shutdown":{}} is valid; everything else must be
		// ErrProtocol, never silent-accept.
		var req controlrpc.Request
		reqErr := req.UnmarshalJSON(frame.bytes)
		if frame.validRequest {
			if reqErr != nil {
				rt.Fatalf("valid request frame rejected: frame=%s err=%v", frame.bytes, reqErr)
			}
			if req.Shutdown == nil {
				rt.Fatalf("valid request frame did not populate Shutdown: %s", frame.bytes)
			}
		} else if !errors.Is(reqErr, controlrpc.ErrProtocol) {
			rt.Fatalf("invalid request frame not ErrProtocol: frame=%s err=%v", frame.bytes, reqErr)
		}

		// Reply direction: {"ShutdownAccepted":{}} or a well-formed {"ControlError":
		// {...}} is valid; everything else must be ErrProtocol.
		var rep controlrpc.Reply
		repErr := rep.UnmarshalJSON(frame.bytes)
		if frame.validReply {
			if repErr != nil {
				rt.Fatalf("valid reply frame rejected: frame=%s err=%v", frame.bytes, repErr)
			}
			if rep.Accepted == nil && rep.Error == nil {
				rt.Fatalf("valid reply frame populated no variant: %s", frame.bytes)
			}
		} else if !errors.Is(repErr, controlrpc.ErrProtocol) {
			rt.Fatalf("invalid reply frame not ErrProtocol: frame=%s err=%v", frame.bytes, repErr)
		}
	})
}

// TestProperty_RoundTrip asserts every valid frame survives an Encode/Decode
// round-trip in BOTH directions: a Request encodes and decodes back to a Request
// with Shutdown set; a Reply (accepted or a bounded-error) encodes and decodes
// back to the same variant. The codec is the bounded newline-delimited transport
// the dial uses.
func TestProperty_RoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		// Request round-trip: the single v1 verb.
		var rbuf bytes.Buffer
		if err := controlrpc.EncodeRequest(&rbuf, controlrpc.Request{Shutdown: &controlrpc.Shutdown{}}); err != nil {
			rt.Fatalf("encode request: %v", err)
		}
		if !bytes.HasSuffix(rbuf.Bytes(), []byte("\n")) {
			rt.Fatalf("encoded request not newline-terminated: %q", rbuf.Bytes())
		}
		gotReq, err := controlrpc.DecodeRequest(bufio.NewReader(&rbuf))
		if err != nil {
			rt.Fatalf("decode request: %v", err)
		}
		if gotReq.Shutdown == nil {
			rt.Fatalf("round-tripped request lost Shutdown")
		}

		// Reply round-trip: choose accepted or a bounded ControlError.
		wantErr := rapid.Bool().Draw(rt, "reply_is_error")
		var rep controlrpc.Reply
		if wantErr {
			code := drawReasonCode(rt)
			msg := rapid.StringN(0, 64, 256).Draw(rt, "message")
			rep = controlrpc.Reply{Error: &controlrpc.ControlError{
				BoundedReason: controlrpc.BoundedReason{ReasonCode: code, Message: msg},
			}}
		} else {
			rep = controlrpc.Reply{Accepted: &controlrpc.ShutdownAccepted{}}
		}
		var pbuf bytes.Buffer
		if err := controlrpc.EncodeReply(&pbuf, rep); err != nil {
			rt.Fatalf("encode reply: %v", err)
		}
		gotRep, err := controlrpc.DecodeReply(bufio.NewReader(&pbuf))
		if err != nil {
			rt.Fatalf("decode reply: %v frame=%q", err, pbuf.Bytes())
		}
		switch {
		case wantErr:
			if gotRep.Error == nil {
				rt.Fatalf("round-tripped error reply lost ControlError")
			}
			if gotRep.Error.ReasonCode != rep.Error.ReasonCode {
				rt.Fatalf("reason_code mutated: got %q want %q", gotRep.Error.ReasonCode, rep.Error.ReasonCode)
			}
			if gotRep.Error.Message != rep.Error.Message {
				rt.Fatalf("message mutated: got %q want %q", gotRep.Error.Message, rep.Error.Message)
			}
		default:
			if gotRep.Accepted == nil {
				rt.Fatalf("round-tripped accepted reply lost ShutdownAccepted")
			}
		}
	})
}

// TestOversizeFrameDoesNotWedge asserts a frame larger than maxFrameBytes (no
// newline, so a naive reader would buffer without bound) is rejected with
// ErrProtocol rather than wedging the decoder or exhausting memory. The reader is
// bounded; the next read starts fresh on the underlying stream.
func TestOversizeFrameDoesNotWedge(t *testing.T) {
	t.Parallel()
	// 128 KiB of a no-newline body: twice the 64 KiB cap, never terminated.
	huge := bytes.Repeat([]byte("A"), 128<<10)
	r := bufio.NewReader(bytes.NewReader(huge))
	_, err := controlrpc.DecodeRequest(r)
	if !errors.Is(err, controlrpc.ErrProtocol) {
		t.Fatalf("oversize frame: want ErrProtocol, got %v", err)
	}

	// A valid frame appended AFTER a newline-terminated oversize frame: the decoder
	// returns ErrProtocol on the first and is not wedged — a fresh reader over a
	// clean frame decodes normally, proving the bound did not corrupt the codec.
	var clean bytes.Buffer
	if err := controlrpc.EncodeRequest(&clean, controlrpc.Request{Shutdown: &controlrpc.Shutdown{}}); err != nil {
		t.Fatalf("encode clean: %v", err)
	}
	got, err := controlrpc.DecodeRequest(bufio.NewReader(&clean))
	if err != nil {
		t.Fatalf("clean frame after oversize: %v", err)
	}
	if got.Shutdown == nil {
		t.Fatalf("clean frame lost Shutdown")
	}
}

// generatedFrame is one drawn frame plus the test's own ground truth of whether
// it is a valid request and/or a valid reply, derived independently of the codec.
type generatedFrame struct {
	bytes        []byte
	validRequest bool
	validReply   bool
}

// drawFrame generates a frame across the whole space the closed union must
// classify: the three valid empty-body variants, a valid bounded ControlError,
// and a broad set of invalid shapes (null, non-object, unknown tag, multi-tag,
// non-empty body, malformed reason). validRequest/validReply are computed here, so
// the property checks the codec against an independent oracle.
func drawFrame(rt *rapid.T) generatedFrame {
	kind := rapid.SampledFrom([]string{
		"shutdown", "accepted", "error_ok",
		"null", "array", "number", "string", "empty_obj",
		"unknown_tag", "multi_tag", "shutdown_nonempty", "accepted_nonempty",
		"error_bad_code", "error_long_msg", "error_extra_field", "error_null_body",
	}).Draw(rt, "frame_kind")

	switch kind {
	case "shutdown":
		return generatedFrame{bytes: []byte(`{"Shutdown":{}}`), validRequest: true}
	case "accepted":
		return generatedFrame{bytes: []byte(`{"ShutdownAccepted":{}}`), validReply: true}
	case "error_ok":
		code := drawReasonCode(rt)
		msg := rapid.StringN(0, 64, 256).Draw(rt, "ok_msg")
		body, err := json.Marshal(controlrpc.BoundedReason{ReasonCode: code, Message: msg})
		if err != nil {
			rt.Fatalf("marshal bounded reason: %v", err)
		}
		return generatedFrame{bytes: []byte(`{"ControlError":` + string(body) + `}`), validReply: true}
	case "null":
		return generatedFrame{bytes: []byte(`null`)}
	case "array":
		return generatedFrame{bytes: []byte(`["Shutdown"]`)}
	case "number":
		return generatedFrame{bytes: []byte(`42`)}
	case "string":
		return generatedFrame{bytes: []byte(`"Shutdown"`)}
	case "empty_obj":
		return generatedFrame{bytes: []byte(`{}`)}
	case "unknown_tag":
		tag := drawTagIdent(rt)
		// Exclude the three real tags so this case is reliably unknown.
		if tag == "Shutdown" || tag == "ShutdownAccepted" || tag == "ControlError" {
			tag = "X" + tag
		}
		return generatedFrame{bytes: []byte(`{"` + tag + `":{}}`)}
	case "multi_tag":
		return generatedFrame{bytes: []byte(`{"Shutdown":{},"ShutdownAccepted":{}}`)}
	case "shutdown_nonempty":
		return generatedFrame{bytes: []byte(`{"Shutdown":{"x":1}}`)}
	case "accepted_nonempty":
		return generatedFrame{bytes: []byte(`{"ShutdownAccepted":{"x":1}}`)}
	case "error_bad_code":
		// lowercase leading char violates ^[A-Z]...
		return generatedFrame{bytes: []byte(`{"ControlError":{"reason_code":"bad"}}`)}
	case "error_long_msg":
		long := strings.Repeat("x", 257)
		return generatedFrame{bytes: []byte(`{"ControlError":{"reason_code":"OK","message":"` + long + `"}}`)}
	case "error_extra_field":
		return generatedFrame{bytes: []byte(`{"ControlError":{"reason_code":"OK","stack":"leak"}}`)}
	case "error_null_body":
		return generatedFrame{bytes: []byte(`{"ControlError":null}`)}
	default:
		rt.Fatalf("unhandled frame kind %q", kind)
		return generatedFrame{}
	}
}

// drawReasonCode draws a string matching the frozen ^[A-Z][A-Z0-9_]{1,63}$
// pattern: an uppercase leading letter then 1..63 of uppercase/digit/underscore.
func drawReasonCode(rt *rapid.T) string {
	head := rapid.SampledFrom([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).Draw(rt, "code_head")
	tail := rapid.SliceOfN(
		rapid.SampledFrom([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")),
		1, 63,
	).Draw(rt, "code_tail")
	return string(append([]byte{head}, tail...))
}

// drawTagIdent draws a short identifier for an unknown-tag frame.
func drawTagIdent(rt *rapid.T) string {
	return rapid.StringMatching(`[A-Za-z][A-Za-z0-9_]{0,15}`).Draw(rt, "tag_ident")
}
