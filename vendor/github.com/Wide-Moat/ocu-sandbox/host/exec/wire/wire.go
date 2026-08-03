// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package wire is the exec-channel control contract, in Go. It mirrors the
// frozen exec-channel JSON Schema as host-side types: the ProcessConnection
// handshake, the ServerMessage and ClientMessage single-key tagged unions, the
// Signal scalar, and the CreateProcess spawn parameters. The types are kept
// honest by validating serialized samples against the identical schema bytes the
// other side uses (see the conformance tests), which is the cross-language
// equivalence proof. No transport or dispatch lives here — only the wire shapes.
package wire

import (
	"bytes"
	"fmt"
)

// Null is a body that marshals to JSON null and unmarshals only from null. It is
// the body type for tags whose schema body is {"type":"null"}, so the
// externally-tagged form is {"Tag":null} (a single-key object), never the bare
// string "Tag".
type Null struct{}

// MarshalJSON renders JSON null.
func (Null) MarshalJSON() ([]byte, error) { return []byte("null"), nil }

// UnmarshalJSON accepts only the JSON literal null.
func (*Null) UnmarshalJSON(b []byte) error {
	if !bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return fmt.Errorf("wire: Null expects JSON null, got %s", b)
	}
	return nil
}

// BoundedReason is a stable error reason plus an optional bounded message. It
// carries no stack traces or internal topology; the length is capped by the
// schema.
type BoundedReason struct {
	ReasonCode string  `json:"reason_code"`
	Message    *string `json:"message,omitempty"`
}

// CreateProcess holds spawn parameters. cmd and args are required; every other
// field is optional and omitted when unset. Optionals are pointers so a zero
// value never leaks a key onto the wire; the boolean defaults are false, so they
// too are omitted when false to keep v1 output minimal (both forms are
// schema-valid).
type CreateProcess struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args"`

	Cwd              *string           `json:"cwd,omitempty"`
	Env              map[string]string `json:"env,omitempty"`
	Rows             *uint16           `json:"rows,omitempty"`
	Cols             *uint16           `json:"cols,omitempty"`
	Timeout          *uint32           `json:"timeout,omitempty"`
	CpuTimeout       *uint32           `json:"cpu_timeout,omitempty"`
	MemoryLimitBytes *uint64           `json:"memory_limit_bytes,omitempty"`
	Uid              *uint32           `json:"uid,omitempty"`
	Gid              *uint32           `json:"gid,omitempty"`

	// BoundPid is schema-nullable (["integer","null"]) and not required. It is
	// omitted when nil; callers that must distinguish "explicitly null" from
	// "absent" should carry that distinction at a higher layer.
	BoundPid *uint32 `json:"bound_pid,omitempty"`

	ClearEnv            bool `json:"clear_env,omitempty"`
	AllowProcessIdReuse bool `json:"allow_process_id_reuse,omitempty"`
	Reattachable        bool `json:"reattachable,omitempty"`
}

// ProcessConnection is the handshake envelope (the client's first or second
// frame). A present CreateReq means spawn; its absence means reattach.
type ProcessConnection struct {
	ProcessId             string         `json:"process_id"`
	CreateReq             *CreateProcess `json:"create_req,omitempty"`
	ExpectedContainerName *string        `json:"expected_container_name,omitempty"`
	WantTraceEvents       *bool          `json:"want_trace_events,omitempty"`
	AcceptCompression     *bool          `json:"accept_compression,omitempty"`
}

// ConnectionCapabilities is the first server frame after the handshake. Both
// flags are always emitted (no omitempty): the schema requires them.
type ConnectionCapabilities struct {
	SupportsTraces      bool `json:"supports_traces"`
	SupportsCompression bool `json:"supports_compression"`
}

// ProcessExited carries the exit code only (0..255).
type ProcessExited struct {
	Code uint8 `json:"code"`
}

// SignalSent reports that a signal was delivered, wrapping the Signal value in a
// {"signal": ...} object.
type SignalSent struct {
	Signal Signal `json:"signal"`
}

// Resize requests a PTY resize; both dimensions are required.
type Resize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// TraceEventMsg is a trace event body, Chrome-Trace-Event-shaped. The body is
// pinned to exactly these five fields and closed (schema
// additionalProperties:false): Name and Ph are required; Cat, Ts, and DurUs are
// optional and omitted when unset. ONE type carries the body in both the server
// and client TraceEvent tags, so the two directions never drift. Ts and DurUs are
// microseconds (uint64 wire domain).
type TraceEventMsg struct {
	Name  string  `json:"name"`
	Ph    string  `json:"ph"`
	Cat   *string `json:"cat,omitempty"`
	Ts    *uint64 `json:"ts,omitempty"`
	DurUs *uint64 `json:"dur_us,omitempty"`
}
