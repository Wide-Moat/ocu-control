// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/jwks"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// buildTestSigner loads a real Ed25519 signer the way buildSigner does at boot,
// over a freshly written key mount, so renderJWKSArtifact exercises the production
// signer.PublicKeys() seam rather than a fake.
func buildTestSigner(t *testing.T) *cred.Signer {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "jwt.key")
	writeTestKey(t, keyPath)
	cfg := config{jwtAlg: "eddsa", jwtSigningKey: keyPath}
	signer, _, err := buildSigner(cfg, state.SystemClock())
	if err != nil {
		t.Fatalf("buildSigner: %v", err)
	}
	return signer
}

// Test_renderJWKSArtifact_Disabled proves the OPTIONAL flag is a clean no-op when
// unset: renderJWKSArtifact returns nil and writes nothing, so the minimal shelf
// boots without storage provisioning. A signer is present here to prove the no-op
// is keyed on the empty path, not on the absence of a signer.
func Test_renderJWKSArtifact_Disabled(t *testing.T) {
	t.Parallel()
	signer := buildTestSigner(t)
	dir := t.TempDir()
	if err := renderJWKSArtifact(config{jwksPath: ""}, signer); err != nil {
		t.Fatalf("renderJWKSArtifact with an unset path returned %v; want nil", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("renderJWKSArtifact wrote %d entries with an unset path; want none", len(entries))
	}
}

// Test_renderJWKSArtifact_Writes proves the SET + signer-present path: the artifact
// is written, parses as a JWKS, and carries the signer's active kid — the served
// document the deploy layer publishes at the edge's remote_jwks URI.
func Test_renderJWKSArtifact_Writes(t *testing.T) {
	t.Parallel()
	signer := buildTestSigner(t)
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := renderJWKSArtifact(config{jwksPath: path}, signer); err != nil {
		t.Fatalf("renderJWKSArtifact: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var set jwks.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("artifact does not parse as a JWKS: %v\n%s", err, raw)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("artifact has %d keys, want 1", len(set.Keys))
	}
	if set.Keys[0].Kid != signer.ActiveKID() {
		t.Fatalf("artifact kid %q != active kid %q", set.Keys[0].Kid, signer.ActiveKID())
	}
}

// Test_renderJWKSArtifact_FailClosedEmpty drives the fail-closed boot path at the
// cmd seam: -jwks-path is set but the signer's PublicKeys() is empty (a nil signer
// stands in for "no signer / no keys"), so renderJWKSArtifact returns a boot-abort
// error that errors.Is(jwks.ErrEmptyKeySet) — never a silently-written empty Set —
// and writes no file.
func Test_renderJWKSArtifact_FailClosedEmpty(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "jwks.json")
	err := renderJWKSArtifact(config{jwksPath: path}, nil)
	if !errors.Is(err, jwks.ErrEmptyKeySet) {
		t.Fatalf("renderJWKSArtifact with no keys = %v, want a boot abort wrapping ErrEmptyKeySet", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("fail-closed render wrote a file (stat err=%v); want no file", statErr)
	}
}
