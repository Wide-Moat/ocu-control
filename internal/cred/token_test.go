// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// TestTokenNeverLogged mints real tokens and drives every clear-text emit
// surface a Token could leak through — fmt verbs, slog, json.Marshal of a
// Token-bearing struct, and an error value — asserting the raw compact JWT
// appears in NONE of them and the redaction sentinel appears in each. The raw
// JWT is reachable only through Reveal, the single audited escape hatch.
func TestTokenNeverLogged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	signer, _ := newTestSigner(t, cred.AlgEdDSA, 10*time.Minute)

	storageTok, err := signer.MintStorageJWT(ctx, cred.StorageMintReq{
		SessionKey:   "host-derived-session-key",
		FilesystemID: "fs-abc",
		Workspace:    "ws-1",
		Org:          "org-1",
		Authz:        cred.AuthorizationMetadata{Scope: "/data", Intent: cred.IntentRead},
	})
	if err != nil {
		t.Fatalf("MintStorageJWT: %v", err)
	}
	execSigner, _ := newTestExecSigner(t)
	execTok, err := execSigner.MintExecJWT(ctx, cred.ExecMintReq{ContainerName: "ocu-ctr-1", RequestedTTL: time.Minute})
	if err != nil {
		t.Fatalf("MintExecJWT: %v", err)
	}

	for name, tok := range map[string]cred.Token{"storage": storageTok, "exec": execTok} {
		raw := tok.Reveal()
		if raw == "" || !strings.Contains(raw, ".") {
			t.Fatalf("%s: Reveal did not return a compact JWT: %q", name, raw)
		}

		// Every emit surface, collected then scanned for the raw JWT.
		emits := map[string]string{
			"%v":            fmt.Sprintf("%v", tok),
			"%s":            fmt.Sprintf("%s", tok),
			"%q":            fmt.Sprintf("%q", tok),
			"%#v":           fmt.Sprintf("%#v", tok),
			"%+v":           fmt.Sprintf("%+v", tok),
			"%x":            fmt.Sprintf("%x", tok),
			"String":        tok.String(),
			"GoString":      tok.GoString(),
			"error-wrap":    fmt.Errorf("rendering mount with token %v: %w", tok, errSentinel).Error(),
			"slog":          slogLine(t, tok),
			"json-token":    mustJSON(t, tok),
			"json-struct":   mustJSON(t, struct{ AuthToken cred.Token }{tok}),
			"json-map":      mustJSON(t, map[string]cred.Token{"auth_token": tok}),
			"marshaltext":   mustText(t, tok),
			"nested-struct": mustJSON(t, struct{ Inner struct{ T cred.Token } }{Inner: struct{ T cred.Token }{T: tok}}),
		}

		for surface, out := range emits {
			if strings.Contains(out, raw) {
				t.Errorf("%s token leaked the raw JWT through %s: %q", name, surface, out)
			}
			if !strings.Contains(out, "Token(REDACTED)") {
				t.Errorf("%s token via %s did not redact to the sentinel: %q", name, surface, out)
			}
		}
	}
}

var errSentinel = fmt.Errorf("sentinel")

// slogLine logs the token as an slog attribute value and returns the rendered
// line; a leaking LogValue would surface the raw JWT here.
func slogLine(t *testing.T, tok cred.Token) string {
	t.Helper()
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	slog.New(h).Info("provisioned mount", slog.Any("auth_token", tok))
	return buf.String()
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

func mustText(t *testing.T, tok cred.Token) string {
	t.Helper()
	b, err := tok.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	return string(b)
}

// TestZeroTokenIsZero confirms a never-minted Token reports IsZero so the
// renderer can refuse an empty auth_token, while a minted one does not.
func TestZeroTokenIsZero(t *testing.T) {
	t.Parallel()
	var zero cred.Token
	if !zero.IsZero() {
		t.Fatal("zero Token must report IsZero")
	}
	execSigner, _ := newTestExecSigner(t)
	tok, err := execSigner.MintExecJWT(context.Background(), cred.ExecMintReq{ContainerName: "c", RequestedTTL: time.Minute})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if tok.IsZero() {
		t.Fatal("a minted Token must not report IsZero")
	}
}
