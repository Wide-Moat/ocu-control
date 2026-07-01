// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import (
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Token is a minted JWT held as a secret. Its String, GoString, Format,
// LogValue, MarshalJSON, and MarshalText ALL redact, so a Token cannot reach a
// log line, an audit Record, a URL/query builder, or an error string by any
// path Go's fmt/slog/json/encoding.TextMarshaler use. The raw compact JWT is
// reachable ONLY through Reveal — the single named escape hatch a reviewer
// greps to enumerate every clear-text materialization. The raw field is
// unexported, so a reflection-based encoder cannot reach it: the redaction is
// structural, not a matter of remembering to call a helper.
type Token struct {
	raw string // unexported: a reflective walker cannot read it as a field
}

// tokenRedaction is the sentinel every redacting surface emits. A
// token-never-logged grep test drives every emit path and asserts this string,
// never the raw JWT, appears. It is a fixed marker, not a credential.
const tokenRedaction = "Token(REDACTED)" //nolint:gosec // G101: redaction sentinel, not a credential

// String redacts: a %s, a Stringer caller, or a default fmt verb yields the
// sentinel.
func (Token) String() string { return tokenRedaction }

// GoString redacts: a %#v never prints the struct with its raw field.
func (Token) GoString() string { return tokenRedaction }

// Format redacts every fmt verb (%v, %s, %q, %x, ...) through a single sink, so
// no verb can route around String/GoString to the raw bytes.
func (Token) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(tokenRedaction)) }

// LogValue redacts under slog: a Token logged as an attribute value emits the
// sentinel, not the JWT.
func (Token) LogValue() slog.Value { return slog.StringValue(tokenRedaction) }

// MarshalJSON redacts: a Token embedded in a struct that is json.Marshal-ed
// emits the sentinel string, never the JWT. The mount-config render therefore
// never emits the raw token by accidentally marshaling a Token-bearing struct;
// the real token reaches the wire only through the private wire struct's
// plain-string field filled via Reveal at the single Marshal boundary.
func (Token) MarshalJSON() ([]byte, error) { return json.Marshal(tokenRedaction) }

// MarshalText redacts: this closes the encoding.TextMarshaler path some URL or
// query builders and structured loggers take.
func (Token) MarshalText() ([]byte, error) { return []byte(tokenRedaction), nil }

// Compile-time assertions that Token satisfies every redacting interface, so a
// refactor that drops a method fails the build, not a test at runtime.
var (
	_ fmt.Stringer           = Token{}
	_ fmt.GoStringer         = Token{}
	_ fmt.Formatter          = Token{}
	_ slog.LogValuer         = Token{}
	_ json.Marshaler         = Token{}
	_ encoding.TextMarshaler = Token{}
)

// IsZero reports the never-minted Token. The mount renderer refuses a zero
// Token (ErrNoCredential) so a config never ships an empty auth_token.
func (t Token) IsZero() bool { return t.raw == "" }

// Reveal returns the raw compact JWT for the ONE legitimate consumer per call
// site: the mount-config wire struct (auth_token) and the control-RPC dial
// Authorization. It is the single audited escape hatch — every clear-text
// materialization is a Reveal call a reviewer can enumerate by grep.
func (t Token) Reveal() string { return t.raw }

// newToken wraps a freshly minted compact JWT. Unexported: only a Signer in
// this package mints, so a Token can never be constructed with attacker-chosen
// bytes from outside the custody core.
func newToken(compact string) Token { return Token{raw: compact} }
