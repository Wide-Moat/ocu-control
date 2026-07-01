// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// The compile-time interface assertions in secretkey.go guarantee that a
// dropped method fails the build, not a runtime test. This file drives every
// emit surface behaviorally.

const rawBody = "sk-ocu-ABC123xyz"

// TestSecretKeyRedactsAllSurfaces drives every emit path — fmt verbs, slog,
// json.Marshal of a SecretKey-bearing struct — and asserts the raw body appears
// in NONE of them and the redaction sentinel appears in each.
func TestSecretKeyRedactsAllSurfaces(t *testing.T) {
	t.Parallel()
	sk := mcpkey.NewSecretKeyForTest(rawBody)
	raw := sk.Reveal()
	if raw != rawBody {
		t.Fatalf("Reveal returned %q; want %q", raw, rawBody)
	}

	emits := map[string]string{
		"%v":          fmt.Sprintf("%v", sk),
		"%s":          fmt.Sprintf("%s", sk),
		"%q":          fmt.Sprintf("%q", sk),
		"%#v":         fmt.Sprintf("%#v", sk),
		"%+v":         fmt.Sprintf("%+v", sk),
		"%x":          fmt.Sprintf("%x", sk),
		"String":      sk.String(),
		"GoString":    sk.GoString(),
		"slog":        secretKeySlogLine(t, sk),
		"json-key":    mustJSONKey(t, sk),
		"json-struct": mustJSONStruct(t, sk),
		"json-map":    mustJSONMap(t, sk),
		"marshaltext": mustTextKey(t, sk),
	}

	const sentinel = "SecretKey(REDACTED)"
	for surface, out := range emits {
		if strings.Contains(out, raw) {
			t.Errorf("SecretKey leaked the raw body through %s: %q", surface, out)
		}
		if !strings.Contains(out, sentinel) {
			t.Errorf("SecretKey via %s did not emit sentinel %q; got: %q", surface, sentinel, out)
		}
	}
}

// TestSecretKeyReveal confirms Reveal returns the exact raw body.
func TestSecretKeyReveal(t *testing.T) {
	t.Parallel()
	sk := mcpkey.NewSecretKeyForTest("sk-ocu-testraw")
	if got := sk.Reveal(); got != "sk-ocu-testraw" {
		t.Fatalf("Reveal = %q; want %q", got, "sk-ocu-testraw")
	}
}

// TestSecretKeyIsZero confirms the zero value reports IsZero and a constructed
// key does not.
func TestSecretKeyIsZero(t *testing.T) {
	t.Parallel()
	zero := mcpkey.ZeroSecretKey()
	if !zero.IsZero() {
		t.Fatal("zero SecretKey must report IsZero")
	}
	sk := mcpkey.NewSecretKeyForTest("sk-ocu-nonzero")
	if sk.IsZero() {
		t.Fatal("constructed SecretKey must not report IsZero")
	}
}

// TestSecretKeyJSONStructEmitsSentinel confirms a SecretKey embedded in a
// struct that is json.Marshal-ed emits the sentinel for that field, never the
// raw body.
func TestSecretKeyJSONStructEmitsSentinel(t *testing.T) {
	t.Parallel()
	sk := mcpkey.NewSecretKeyForTest("sk-ocu-embedtest")
	type payload struct {
		Key mcpkey.SecretKey `json:"key"`
	}
	b, err := json.Marshal(payload{Key: sk})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	out := string(b)
	if strings.Contains(out, "sk-ocu-embedtest") {
		t.Errorf("raw body leaked in JSON struct: %s", out)
	}
	if !strings.Contains(out, "SecretKey(REDACTED)") {
		t.Errorf("sentinel absent from JSON struct: %s", out)
	}
}

// -- helpers -----------------------------------------------------------------

func secretKeySlogLine(t *testing.T, sk mcpkey.SecretKey) string {
	t.Helper()
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	slog.New(h).Info("issued key", slog.Any("key", sk))
	return buf.String()
}

func mustJSONKey(t *testing.T, sk mcpkey.SecretKey) string {
	t.Helper()
	b, err := json.Marshal(sk)
	if err != nil {
		t.Fatalf("json.Marshal(sk): %v", err)
	}
	return string(b)
}

func mustJSONStruct(t *testing.T, sk mcpkey.SecretKey) string {
	t.Helper()
	b, err := json.Marshal(struct{ K mcpkey.SecretKey }{K: sk})
	if err != nil {
		t.Fatalf("json.Marshal(struct): %v", err)
	}
	return string(b)
}

func mustJSONMap(t *testing.T, sk mcpkey.SecretKey) string {
	t.Helper()
	b, err := json.Marshal(map[string]mcpkey.SecretKey{"key": sk})
	if err != nil {
		t.Fatalf("json.Marshal(map): %v", err)
	}
	return string(b)
}

func mustTextKey(t *testing.T, sk mcpkey.SecretKey) string {
	t.Helper()
	b, err := sk.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	return string(b)
}
