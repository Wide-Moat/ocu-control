// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package wire

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// ServerMessage is a server-to-client control frame: a single-key tagged union
// with one pointer field per schema tag. Exactly one field is set per frame;
// MarshalJSON enforces that invariant. Null-bodied tags use *Null so the wire
// form is {"Tag":null}; object-bodied tags use their body struct. The TraceEvent
// tag carries the pinned, closed TraceEventMsg body; the V2 tags stay
// *json.RawMessage (the schema closes them to an empty object, so the raw body
// round-trips {} faithfully). Only v1 tags are emitted in this phase.
type ServerMessage struct {
	ConnectionCapabilities *ConnectionCapabilities `json:"ConnectionCapabilities,omitempty"`

	ProcessCreated   *Null            `json:"ProcessCreated,omitempty"`
	ProcessCreatedV2 *json.RawMessage `json:"ProcessCreatedV2,omitempty"`

	AttachedToProcess   *Null            `json:"AttachedToProcess,omitempty"`
	AttachedToProcessV2 *json.RawMessage `json:"AttachedToProcessV2,omitempty"`

	ProcessNotRunning      *Null `json:"ProcessNotRunning,omitempty"`
	ProcessAlreadyAttached *Null `json:"ProcessAlreadyAttached,omitempty"`

	FailedToStart                         *BoundedReason `json:"FailedToStart,omitempty"`
	FailedToStartProcessWithSameIdRunning *Null          `json:"FailedToStartProcessWithSameIdRunning,omitempty"`
	InfraError                            *BoundedReason `json:"InfraError,omitempty"`

	ExpectStdOut *Null `json:"ExpectStdOut,omitempty"`
	StdOutEOF    *Null `json:"StdOutEOF,omitempty"`
	ExpectStdErr *Null `json:"ExpectStdErr,omitempty"`
	StdErrEOF    *Null `json:"StdErrEOF,omitempty"`

	SignalSent         *SignalSent    `json:"SignalSent,omitempty"`
	FailedToSendSignal *BoundedReason `json:"FailedToSendSignal,omitempty"`
	InvalidSignal      *BoundedReason `json:"InvalidSignal,omitempty"`

	TraceEvent *TraceEventMsg `json:"TraceEvent,omitempty"`

	ProcessExited        *ProcessExited `json:"ProcessExited,omitempty"`
	ProcessTimedOut      *Null          `json:"ProcessTimedOut,omitempty"`
	ProcessCpuTimedOut   *Null          `json:"ProcessCpuTimedOut,omitempty"`
	ProcessOutOfMemory   *Null          `json:"ProcessOutOfMemory,omitempty"`
	ContainerOutOfMemory *Null          `json:"ContainerOutOfMemory,omitempty"`
	ShuttingDown         *Null          `json:"ShuttingDown,omitempty"`
}

// MarshalJSON marshals the union and asserts the frame carries exactly one tag.
// Default struct marshalling already yields the single non-nil field as the lone
// key; the guard catches a 0- or 2-key bug at the boundary, which the schema's
// minProperties:1/maxProperties:1 would otherwise reject downstream.
func (m ServerMessage) MarshalJSON() ([]byte, error) {
	type raw ServerMessage
	return marshalSingleKey("ServerMessage", raw(m))
}

// UnmarshalJSON decodes a single-key frame. Default struct decoding leaves a
// *Null field nil when its body is JSON null (encoding/json sets a pointer to
// nil on null rather than allocating), which would erase null-bodied tags such
// as ProcessCreated. A future/unknown top-level key matches no field and is
// silently ignored (forward compatibility). The known tag, if present, is
// decoded into its field — allocating &Null{} for null-bodied tags so the tag's
// presence survives the round trip.
func (m *ServerMessage) UnmarshalJSON(b []byte) error {
	type raw ServerMessage
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*m = ServerMessage(r)
	return reviveNullTags(b, m)
}

// ClientMessage is a client-to-server control frame: a single-key tagged union,
// one pointer field per schema tag, exactly one set per frame.
type ClientMessage struct {
	// SendSignal's body IS the Signal value directly ({"SendSignal":9} or
	// {"SendSignal":"SIGKILL"}); Signal's own marshalling renders the int|string.
	SendSignal *Signal `json:"SendSignal,omitempty"`

	ExpectStdIn *Null   `json:"ExpectStdIn,omitempty"`
	StdInEOF    *Null   `json:"StdInEOF,omitempty"`
	Resize      *Resize `json:"Resize,omitempty"`
	Detach      *Null   `json:"Detach,omitempty"`
	KeepAlive   *Null   `json:"KeepAlive,omitempty"`
	Closed      *Null   `json:"Closed,omitempty"`

	TraceEvent *TraceEventMsg `json:"TraceEvent,omitempty"`
}

// MarshalJSON marshals the union and asserts exactly one tag is set.
func (m ClientMessage) MarshalJSON() ([]byte, error) {
	type raw ClientMessage
	return marshalSingleKey("ClientMessage", raw(m))
}

// UnmarshalJSON decodes a single-key frame, reviving null-bodied tags (see the
// ServerMessage.UnmarshalJSON note) and ignoring unknown top-level keys.
func (m *ClientMessage) UnmarshalJSON(b []byte) error {
	type raw ClientMessage
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*m = ClientMessage(r)
	return reviveNullTags(b, m)
}

// nullType is the reflect.Type of *Null, used to identify null-bodied tags.
var nullType = reflect.TypeOf((*Null)(nil))

// reviveNullTags re-populates *Null fields that default decoding left nil.
// encoding/json sets a pointer field to nil when its JSON body is null, so a
// null-bodied tag like {"ProcessCreated":null} would lose its presence. For each
// top-level key in b that maps (by json tag) to a *Null field, this sets that
// field to &Null{}, restoring the tag. msg must be a pointer to the union struct.
func reviveNullTags(b []byte, msg any) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return err
	}
	sv := reflect.ValueOf(msg).Elem()
	st := sv.Type()
	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		if field.Type != nullType {
			continue
		}
		tag := jsonTagName(field)
		if raw, ok := top[tag]; ok && isJSONNull(raw) {
			sv.Field(i).Set(reflect.ValueOf(&Null{}))
		}
	}
	return nil
}

// jsonTagName returns the wire key for a struct field (the json tag's name, or
// the field name when no tag is present).
func jsonTagName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if name, _, _ := strings.Cut(tag, ","); name != "" {
		return name
	}
	return f.Name
}

func isJSONNull(b json.RawMessage) bool {
	return strings.TrimSpace(string(b)) == "null"
}

// marshalSingleKey marshals v with default struct rules, then probes the result
// and errors unless it is a single-key object.
func marshalSingleKey(kind string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("wire: %s did not marshal to an object: %w", kind, err)
	}
	if len(probe) != 1 {
		return nil, fmt.Errorf("wire: %s must have exactly one variant set, got %d", kind, len(probe))
	}
	return b, nil
}
