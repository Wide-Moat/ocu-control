// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package controlrpc is the host-dials-guest control-RPC surface (ADR-0018): the
// host opens a host-owned Unix domain socket that lives in a 0700 host-owned
// directory inside the guest's handoff sock dir, writes one newline-delimited
// JSON request frame, reads one reply frame, and closes. The guest never dials
// Control; the host dials the guest, so an unreachable control channel grants the
// guest no new authority (NFR-SEC-01).
//
// The wire is a closed externally-tagged union: exactly one top-level key names
// the verb (Request) or the reply variant (Reply). An unknown tag, a multi-tag
// frame, a null body, or a non-empty Shutdown body is a HARD protocol error
// (ErrProtocol) on both sides — never silent-accept (the frozen
// contracts/control/control-rpc.schema.json discipline). v1 carries a single
// Shutdown verb: an advisory cooperative SIGTERM advance-grace hint, NOT a
// teardown gate. ShutdownAccepted is the only success reply; it is NOT a
// completion claim — the host-driven finalizer (NFR-SEC-65) is authoritative and
// the force-remove never waits on the reply.
package controlrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrProtocol is the single hard protocol-error sentinel both directions raise on
// a malformed frame: an unknown top-level tag, a multi-tag frame, a null body, a
// non-empty Shutdown/ShutdownAccepted body, or a frame that overruns
// maxFrameBytes. It is never recovered into a silent default — a peer that emits
// a frame this rejects has spoken a verb outside the frozen union, and the closed
// union fails closed rather than guessing a verb.
var ErrProtocol = errors.New("controlrpc: hard protocol error")

// requestTagShutdown is the sole v1 request discriminator. A future verb is an
// additive member (NFR-IC-04), never an open extension point; an unknown tag is
// ErrProtocol here, not a forward-compat hole.
const requestTagShutdown = "Shutdown"

// replyTagAccepted and replyTagError are the two v1 reply discriminators. The
// request and reply arms share no tag, so a frame can be classified to exactly
// one direction by its key.
const (
	replyTagAccepted = "ShutdownAccepted"
	replyTagError    = "ControlError"
)

// Shutdown is the v1 request body: an EMPTY object {}, NOT null. It carries no
// session or container_name — the authority is the host-attested caller identity
// on the host-owned 0700 UDS (NFR-SEC-43/NFR-SEC-76), so there is no body field
// to forge. The empty-object shape (not null) leaves room for a future additive
// x-ocu-tbd field without changing the tag's JSON type.
type Shutdown struct{}

// ShutdownAccepted is the v1 success reply: an EMPTY object. It signals the guest
// has begun the cooperative SIGTERM phase; it is NOT a completion claim. The
// host-driven finalizer decides whether teardown is complete and overrides a
// guest that skips the cooperative phase (P2-T2).
type ShutdownAccepted struct{}

// BoundedReason is the bounded error envelope (NFR-SEC-51): a stable reason_code
// matching ^[A-Z][A-Z0-9_]{1,63}$ and an optional message capped at 256 runes.
// The message carries no stack trace or internal topology. It mirrors the exec
// channel's BoundedReason field-for-field.
type BoundedReason struct {
	ReasonCode string `json:"reason_code"`
	Message    string `json:"message,omitempty"`
}

// ControlError is the guest->host failure reply: a request the guest could not
// accept or process (unknown tag, malformed body, internal failure). The host
// treats any non-ShutdownAccepted reply, and any transport drop, as
// non-authoritative for teardown — the finalizer proceeds regardless.
type ControlError struct {
	BoundedReason
}

// Request is the host->guest closed externally-tagged union. Exactly one of its
// variant pointers is non-nil; v1 has the single Shutdown member. It marshals to
// {"Shutdown":{}} and unmarshals with a hard ErrProtocol on an unknown tag, a
// multi-tag frame, or a null/non-empty body — the mandatory closed-union
// property-test target.
type Request struct {
	Shutdown *Shutdown
}

// Reply is the guest->host closed externally-tagged union: exactly one of
// ShutdownAccepted (the only v1 success) or ControlError. It applies the same
// hard-error discipline as Request.
type Reply struct {
	Accepted *ShutdownAccepted
	Error    *ControlError
}

// MarshalJSON emits the externally-tagged Request frame: {"Shutdown":{}} for the
// v1 verb. An empty Request (no variant set) is itself a protocol error — the
// host never sends a tagless frame.
func (r Request) MarshalJSON() ([]byte, error) {
	if r.Shutdown == nil {
		return nil, fmt.Errorf("%w: request carries no verb", ErrProtocol)
	}
	// The Shutdown body is the empty object {}, not null, per the frozen schema.
	return []byte(`{"` + requestTagShutdown + `":{}}`), nil
}

// UnmarshalJSON parses one externally-tagged Request frame and FAILS CLOSED on
// anything outside the v1 union: a null frame, a non-object, a multi-tag frame, an
// unknown tag, or a non-empty Shutdown body all yield ErrProtocol. It never
// silent-accepts an unrecognized verb.
func (r *Request) UnmarshalJSON(b []byte) error {
	raw, err := singleTag(b)
	if err != nil {
		return err
	}
	if raw.tag != requestTagShutdown {
		return fmt.Errorf("%w: unknown request tag %q", ErrProtocol, raw.tag)
	}
	if err := decodeEmptyBody(raw.body); err != nil {
		return err
	}
	*r = Request{Shutdown: &Shutdown{}}
	return nil
}

// MarshalJSON emits the externally-tagged Reply frame: {"ShutdownAccepted":{}} or
// {"ControlError":{...}}. Exactly one variant must be set; neither or both is a
// protocol error.
func (r Reply) MarshalJSON() ([]byte, error) {
	switch {
	case r.Accepted != nil && r.Error == nil:
		return []byte(`{"` + replyTagAccepted + `":{}}`), nil
	case r.Error != nil && r.Accepted == nil:
		body, err := json.Marshal(r.Error.BoundedReason)
		if err != nil {
			return nil, fmt.Errorf("controlrpc: marshal ControlError: %w", err)
		}
		// Assemble {"ControlError":<body>} without a precomputed make capacity:
		// a size hint summed from the tag and body lengths reads as an
		// allocation-overflow risk to static analysis, and the bytes.Buffer
		// grows itself. The emitted frame is byte-for-byte the same closed
		// externally-tagged object — tag, ':', the marshalled body, '}'.
		var out bytes.Buffer
		out.WriteString(`{"`)
		out.WriteString(replyTagError)
		out.WriteString(`":`)
		out.Write(body)
		out.WriteByte('}')
		return out.Bytes(), nil
	default:
		return nil, fmt.Errorf("%w: reply must carry exactly one variant", ErrProtocol)
	}
}

// UnmarshalJSON parses one externally-tagged Reply frame, failing closed with
// ErrProtocol on a null/non-object frame, a multi-tag frame, an unknown tag, a
// non-empty ShutdownAccepted body, or a ControlError body that violates the
// bounded-reason shape (a malformed reason_code or an unknown field).
func (r *Reply) UnmarshalJSON(b []byte) error {
	raw, err := singleTag(b)
	if err != nil {
		return err
	}
	switch raw.tag {
	case replyTagAccepted:
		if err := decodeEmptyBody(raw.body); err != nil {
			return err
		}
		*r = Reply{Accepted: &ShutdownAccepted{}}
		return nil
	case replyTagError:
		reason, err := decodeBoundedReason(raw.body)
		if err != nil {
			return err
		}
		*r = Reply{Error: &ControlError{BoundedReason: reason}}
		return nil
	default:
		return fmt.Errorf("%w: unknown reply tag %q", ErrProtocol, raw.tag)
	}
}

// taggedFrame is one classified frame: its single top-level tag and the raw bytes
// of that tag's body.
type taggedFrame struct {
	tag  string
	body json.RawMessage
}

// singleTag enforces the closed externally-tagged union shape on a raw frame: it
// must be a JSON object (not null, not an array, not a scalar) with EXACTLY one
// top-level key. A null frame, a non-object, an empty object, or a multi-tag
// frame is ErrProtocol. The returned body is left undecoded so the caller can
// apply the per-variant shape with DisallowUnknownFields.
func singleTag(b []byte) (taggedFrame, error) {
	trimmed := bytes.TrimSpace(b)
	if bytes.Equal(trimmed, []byte("null")) {
		return taggedFrame{}, fmt.Errorf("%w: null frame", ErrProtocol)
	}
	// A top-level object is the only valid frame shape; a number, string, bool,
	// or array decodes into the map below as a type error, which we map to
	// ErrProtocol so no non-object frame is silently accepted.
	var fields map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fields); err != nil {
		return taggedFrame{}, fmt.Errorf("%w: not a tagged object: %v", ErrProtocol, err)
	}
	if dec.More() {
		// Trailing tokens after the object (e.g. two concatenated objects) are not a
		// single frame.
		return taggedFrame{}, fmt.Errorf("%w: trailing data after frame", ErrProtocol)
	}
	if len(fields) != 1 {
		return taggedFrame{}, fmt.Errorf("%w: frame must carry exactly one tag, got %d", ErrProtocol, len(fields))
	}
	for tag, body := range fields {
		return taggedFrame{tag: tag, body: body}, nil
	}
	// Unreachable: len(fields) == 1 is guaranteed above.
	return taggedFrame{}, fmt.Errorf("%w: empty frame", ErrProtocol)
}

// decodeEmptyBody asserts a variant body is the EMPTY object {} the schema fixes
// for Shutdown and ShutdownAccepted: null, a non-object, or any field present is
// ErrProtocol. The empty-object-not-null rule is structural here so a future
// additive field is a deliberate schema bump, not a silently tolerated extra key.
func decodeEmptyBody(body json.RawMessage) error {
	trimmed := bytes.TrimSpace(body)
	if bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("%w: body must be an empty object, not null", ErrProtocol)
	}
	var empty struct{}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&empty); err != nil {
		return fmt.Errorf("%w: body must be an empty object: %v", ErrProtocol, err)
	}
	return nil
}

// boundedReasonCodePattern is the frozen reason_code shape ^[A-Z][A-Z0-9_]{1,63}$:
// an uppercase leading letter then 1..63 of uppercase/digit/underscore (2..64
// chars total). validateReasonCode applies it without a regexp dependency so the
// codec stays a leaf.
const (
	boundedReasonCodeMin = 2
	boundedReasonCodeMax = 64
	boundedMessageMax    = 256
)

// decodeBoundedReason decodes a ControlError body with DisallowUnknownFields and
// validates the bounded shape: reason_code must match the frozen pattern and
// message must be at most 256 runes. A malformed body is ErrProtocol so a guest
// cannot smuggle an unbounded or oddly-shaped reason past the host decoder.
func decodeBoundedReason(body json.RawMessage) (BoundedReason, error) {
	trimmed := bytes.TrimSpace(body)
	if bytes.Equal(trimmed, []byte("null")) {
		return BoundedReason{}, fmt.Errorf("%w: ControlError body is null", ErrProtocol)
	}
	var reason BoundedReason
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reason); err != nil {
		return BoundedReason{}, fmt.Errorf("%w: malformed ControlError body: %v", ErrProtocol, err)
	}
	if !validReasonCode(reason.ReasonCode) {
		return BoundedReason{}, fmt.Errorf("%w: reason_code %q violates pattern", ErrProtocol, reason.ReasonCode)
	}
	if len([]rune(reason.Message)) > boundedMessageMax {
		return BoundedReason{}, fmt.Errorf("%w: message exceeds %d runes", ErrProtocol, boundedMessageMax)
	}
	return reason, nil
}

// validReasonCode reports whether s matches ^[A-Z][A-Z0-9_]{1,63}$: an uppercase
// leading letter, then 1..63 uppercase/digit/underscore, for 2..64 chars total.
func validReasonCode(s string) bool {
	if len(s) < boundedReasonCodeMin || len(s) > boundedReasonCodeMax {
		return false
	}
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		isUpper := c >= 'A' && c <= 'Z'
		isDigit := c >= '0' && c <= '9'
		if !isUpper && !isDigit && c != '_' {
			return false
		}
	}
	return true
}
