// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// TestLoadSignerFailClosed asserts the Signer refuses to construct on a missing
// or garbage mount, on a wrong-family key, and on a structurally invalid config —
// there is no daemon-default key, so a misconfigured deployment cannot boot a
// custody core (NFR-SEC-25).
func TestLoadSignerFailClosed(t *testing.T) {
	t.Parallel()
	clk := state.NewFakeClock(testStart)
	okCfg := cred.Config{Alg: cred.AlgEdDSA, StorageTTL: time.Minute}

	t.Run("missing-mount", func(t *testing.T) {
		t.Parallel()
		_, err := cred.LoadSignerFromMount(filepath.Join(t.TempDir(), "absent.key"), clk, okCfg)
		if !errors.Is(err, cred.ErrSigningKeyMissing) {
			t.Fatalf("missing mount: want ErrSigningKeyMissing, got %v", err)
		}
	})

	t.Run("garbage-bytes", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "garbage.key")
		if err := os.WriteFile(p, []byte("not a pkcs8 key"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := cred.LoadSignerFromMount(p, clk, okCfg)
		if !errors.Is(err, cred.ErrSigningKeyInvalid) {
			t.Fatalf("garbage bytes: want ErrSigningKeyInvalid, got %v", err)
		}
	})

	t.Run("wrong-family", func(t *testing.T) {
		t.Parallel()
		// An Ed25519 key offered to an ES256 deployment must be rejected.
		edPath := writeKeyMount(t, cred.AlgEdDSA)
		_, err := cred.LoadSignerFromMount(edPath, clk, cred.Config{Alg: cred.AlgES256, StorageTTL: time.Minute})
		if !errors.Is(err, cred.ErrSigningKeyInvalid) {
			t.Fatalf("wrong family: want ErrSigningKeyInvalid, got %v", err)
		}
	})

	t.Run("nonpositive-ttl", func(t *testing.T) {
		t.Parallel()
		_, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgEdDSA), clk, cred.Config{Alg: cred.AlgEdDSA, StorageTTL: 0})
		if !errors.Is(err, cred.ErrConfig) {
			t.Fatalf("zero TTL: want ErrConfig, got %v", err)
		}
	})

	t.Run("es256-loads", func(t *testing.T) {
		t.Parallel()
		s, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgES256), clk, cred.Config{Alg: cred.AlgES256, StorageTTL: time.Minute})
		if err != nil {
			t.Fatalf("es256 load: %v", err)
		}
		if s.ActiveKID() == "" {
			t.Fatal("es256 signer has empty kid")
		}
	})
}

// TestMintStorageScopeRefusals asserts the weak Storage-JWT mint fail-closes on a
// missing or invalid scope: an empty filesystem_id, an invalid intent, and a
// downloadable-true with no scope are all ErrMintScope.
func TestMintStorageScopeRefusals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	signer, _ := newTestSigner(t, cred.AlgEdDSA, time.Minute)

	cases := []struct {
		name string
		req  cred.StorageMintReq
	}{
		{"empty-filesystem-id", cred.StorageMintReq{Authz: cred.AuthorizationMetadata{Intent: cred.IntentRead}}},
		{"invalid-intent", cred.StorageMintReq{FilesystemID: "fs", Authz: cred.AuthorizationMetadata{Intent: cred.Intent("delete")}}},
		{"empty-intent", cred.StorageMintReq{FilesystemID: "fs", Authz: cred.AuthorizationMetadata{}}},
		{"downloadable-no-scope", cred.StorageMintReq{FilesystemID: "fs", Authz: cred.AuthorizationMetadata{Intent: cred.IntentRead, Downloadable: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := signer.MintStorageJWT(ctx, tc.req)
			if !errors.Is(err, cred.ErrMintScope) {
				t.Fatalf("%s: want ErrMintScope, got %v", tc.name, err)
			}
		})
	}
}

// The exec mint's empty-container_name refusal now lives on *ExecSigner and is
// covered by TestExecSignerRefusesEmptyContainerName in execsigner_test.go — the
// storage Signer no longer mints exec JWTs (ADR-0013 key separation).

// TestStorageJWTDistinctJTIAcrossInstants kills the nano-byte-extraction mutant in
// deriveJTI: two mints for the SAME session at DISTINCT instants must get DISTINCT
// jti handles (so the Revoker indexes each mint separately). If the mint instant's
// nanoseconds stopped mixing into the derived handle (the survived no-op mutant on
// the byte-extraction loop), both mints would collide on one jti and this fails.
func TestStorageJWTDistinctJTIAcrossInstants(t *testing.T) {
	t.Parallel()
	signer, clk := newTestSigner(t, cred.AlgEdDSA, 10*time.Minute)
	req := cred.StorageMintReq{
		SessionKey:   "host-session-key",
		FilesystemID: "fs-jti",
		Authz:        cred.AuthorizationMetadata{Intent: cred.IntentRead},
	}

	tok1, err := signer.MintStorageJWT(context.Background(), req)
	if err != nil {
		t.Fatalf("mint 1: %v", err)
	}
	// Advance by a sub-second amount so ONLY the nanosecond bytes differ — the exact
	// bytes the extraction loop mixes in. A whole-second advance would also move the
	// exp claim; the point here is that the nano bytes alone change the jti.
	clk.Advance(1234 * time.Nanosecond)
	tok2, err := signer.MintStorageJWT(context.Background(), req)
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}

	jti1 := jtiOf(t, tok1.Reveal())
	jti2 := jtiOf(t, tok2.Reveal())
	if jti1 == "" || jti2 == "" {
		t.Fatalf("empty jti: %q / %q", jti1, jti2)
	}
	if jti1 == jti2 {
		t.Fatalf("two mints at distinct instants share jti %q — the mint-instant nanoseconds are not mixed into the handle", jti1)
	}
}

// jtiOf decodes the jti claim from a compact JWS payload.
func jtiOf(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return claims.JTI
}
