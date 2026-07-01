// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey

import (
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
)

// SecretKey is a minted sk-ocu- credential held as a secret. Its String,
// GoString, Format, LogValue, MarshalJSON, and MarshalText ALL redact, so a
// SecretKey cannot reach a log line, an audit Record, a URL/query builder, or
// an error string by any path Go's fmt/slog/json/encoding.TextMarshaler use.
// The raw sk-ocu- key is reachable ONLY through Reveal — the single named
// escape hatch a reviewer greps to enumerate every clear-text materialization.
// The raw field is unexported, so a reflection-based encoder cannot read it:
// the redaction is structural, not a matter of remembering to call a helper.
type SecretKey struct {
	raw string // unexported: a reflective walker cannot read it as a field
}

// secretKeyRedaction is the sentinel every redacting surface emits. A
// never-logged grep test drives every emit path and asserts this string, never
// the raw sk-ocu- key, appears. It is a fixed marker, not a credential.
const secretKeyRedaction = "SecretKey(REDACTED)" //nolint:gosec // G101: redaction sentinel, not a credential

// String redacts: a %s, a Stringer caller, or a default fmt verb yields the
// sentinel.
func (SecretKey) String() string { return secretKeyRedaction }

// GoString redacts: a %#v never prints the struct with its raw field.
func (SecretKey) GoString() string { return secretKeyRedaction }

// Format redacts every fmt verb (%v, %s, %q, %x, ...) through a single sink,
// so no verb can route around String/GoString to the raw bytes.
func (SecretKey) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(secretKeyRedaction)) }

// LogValue redacts under slog: a SecretKey logged as an attribute value emits
// the sentinel, not the raw key.
func (SecretKey) LogValue() slog.Value { return slog.StringValue(secretKeyRedaction) }

// MarshalJSON redacts: a SecretKey embedded in a struct that is json.Marshal-ed
// emits the sentinel string, never the raw key. The operator CLI render
// therefore never emits the raw key by accidentally marshaling a
// SecretKey-bearing struct; the raw key reaches the shown-once output only
// through Reveal at the single CLI-render call site.
func (SecretKey) MarshalJSON() ([]byte, error) { return json.Marshal(secretKeyRedaction) }

// MarshalText redacts: this closes the encoding.TextMarshaler path some URL or
// query builders and structured loggers take.
func (SecretKey) MarshalText() ([]byte, error) { return []byte(secretKeyRedaction), nil }

// Compile-time assertions that SecretKey satisfies every redacting interface,
// so a refactor that drops a method fails the build, not a test at runtime.
var (
	_ fmt.Stringer           = SecretKey{}
	_ fmt.GoStringer         = SecretKey{}
	_ fmt.Formatter          = SecretKey{}
	_ slog.LogValuer         = SecretKey{}
	_ json.Marshaler         = SecretKey{}
	_ encoding.TextMarshaler = SecretKey{}
)

// IsZero reports the never-minted SecretKey. The operator CLI and record-store
// path refuse a zero SecretKey so a create response never ships an empty key.
func (s SecretKey) IsZero() bool { return s.raw == "" }

// Reveal returns the raw sk-ocu- key for the ONE legitimate consumer per call
// site: the operator CLI shown-once render. It is the single audited escape
// hatch — every clear-text materialization is a Reveal call a reviewer can
// enumerate by grep.
func (s SecretKey) Reveal() string { return s.raw }

// newSecretKey wraps a freshly minted sk-ocu- key. Unexported: only a Minter
// in this package mints, so a SecretKey can never be constructed with
// attacker-chosen bytes from outside the custody core.
func newSecretKey(raw string) SecretKey { return SecretKey{raw: raw} }
