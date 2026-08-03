// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package wire

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ErrProtocol is the control-channel protocol-error sentinel. It is returned
// whenever a control frame violates the closed-union cardinality or an empty
// body is not the literal {} object. No sentinel of this name is shared in the
// package, so it is defined here; callers compare with errors.Is.
var ErrProtocol = errors.New("control: protocol error")

// emptyObject is the body carrier for the control Shutdown and ShutdownAccepted
// tags. Those bodies are empty OBJECTS (schema type:object,
// additionalProperties:false) → JSON {}. wire.Null marshals to null and would
// emit {"Shutdown":null}, which the schema rejects, so Null is deliberately not
// used here. emptyObject marshals to {} and unmarshals only from {}; any other
// body (including null) is a protocol error.
type emptyObject struct{}

// MarshalJSON renders the literal empty object {}.
func (emptyObject) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// UnmarshalJSON accepts only the literal empty object {} (whitespace-trimmed);
// every other body, including null, yields ErrProtocol.
func (*emptyObject) UnmarshalJSON(b []byte) error {
	if !bytes.Equal(bytes.TrimSpace(b), []byte("{}")) {
		return ErrProtocol
	}
	return nil
}

// ControlRequest is a host-to-guest control frame: an externally-tagged closed
// union. v1 carries exactly one tag, Shutdown, whose body is an empty object.
type ControlRequest struct {
	Shutdown *emptyObject `json:"Shutdown,omitempty"`
}

// ControlReply is a guest-to-host control frame: an externally-tagged closed
// union. ShutdownAccepted's body is an empty object; ControlError reuses the
// shared BoundedReason (a stable reason_code plus an optional bounded message).
type ControlReply struct {
	ShutdownAccepted *emptyObject   `json:"ShutdownAccepted,omitempty"`
	ControlError     *BoundedReason `json:"ControlError,omitempty"`
}

// NewShutdownRequest builds the {"Shutdown":{}} request frame.
func NewShutdownRequest() ControlRequest {
	return ControlRequest{Shutdown: &emptyObject{}}
}

// NewShutdownAcceptedReply builds the {"ShutdownAccepted":{}} reply frame.
// ShutdownAccepted is advisory: it means the cooperative shutdown phase was
// entered, not that shutdown has completed.
func NewShutdownAcceptedReply() ControlReply {
	return ControlReply{ShutdownAccepted: &emptyObject{}}
}

// NewControlErrorReply builds a {"ControlError":{...}} reply frame. reason_code
// pattern validation is the schema's job (BoundedReason holds a plain string);
// callers constructing the type outside the conformance boundary must supply a
// schema-valid code.
func NewControlErrorReply(code string, msg *string) ControlReply {
	return ControlReply{ControlError: &BoundedReason{ReasonCode: code, Message: msg}}
}

// ParseControlReply decodes a guest-to-host control frame and enforces the
// closed-union cardinality that json.Unmarshal does not: Go silently leaves all
// fields nil for an unknown tag, silently accepts multiple tags, and silently
// drops a key that belongs to the OTHER arm (e.g. a request tag in a reply
// frame). A correct closed union therefore requires both that the frame has
// exactly one top-level key AND that the single mapped union field is non-nil.
// A malformed body, an unknown tag (0 mapped fields), a multi-tag frame (>1 top
// key), a cross-arm tag (the lone top key maps to no reply field), or an empty
// body that is not {} all return ErrProtocol.
func ParseControlReply(b []byte) (ControlReply, error) {
	var r ControlReply
	if err := json.Unmarshal(b, &r); err != nil {
		return r, ErrProtocol
	}
	if topLevelKeyCount(b) != 1 || controlReplyTagCount(&r) != 1 {
		return r, ErrProtocol
	}
	return r, nil
}

// ParseControlRequest decodes a host-to-guest control frame with the same
// closed-union enforcement as ParseControlReply: zero tags (unknown verb), a
// multi-tag frame, or a cross-arm tag (a reply tag in a request frame) all
// return ErrProtocol.
func ParseControlRequest(b []byte) (ControlRequest, error) {
	var r ControlRequest
	if err := json.Unmarshal(b, &r); err != nil {
		return r, ErrProtocol
	}
	if topLevelKeyCount(b) != 1 || controlRequestTagCount(&r) != 1 {
		return r, ErrProtocol
	}
	return r, nil
}

// topLevelKeyCount returns the number of top-level keys in a JSON object frame,
// or -1 if the bytes are not a JSON object. It is what closes the cross-arm hole
// json.Unmarshal leaves open: a key belonging to the other union arm is dropped
// silently by struct decoding, so the mapped-field count alone cannot see it,
// but the raw top-level key count can. The schema rejects such a frame via
// maxProperties:1 + additionalProperties:false; this is the Go-side equivalent.
func topLevelKeyCount(b []byte) int {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return -1
	}
	return len(m)
}

// controlReplyTagCount counts the non-nil union pointers in a ControlReply.
func controlReplyTagCount(r *ControlReply) int {
	n := 0
	if r.ShutdownAccepted != nil {
		n++
	}
	if r.ControlError != nil {
		n++
	}
	return n
}

// controlRequestTagCount counts the non-nil union pointers in a ControlRequest.
func controlRequestTagCount(r *ControlRequest) int {
	n := 0
	if r.Shutdown != nil {
		n++
	}
	return n
}
