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
	// A structurally VALID config: the iss/aud pins are part of that validity now,
	// so the mount/key subtests below reach their own fences instead of tripping the
	// unpinned-config refusal.
	okCfg := cred.Config{
		Alg:             cred.AlgEdDSA,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		StorageTTL:      time.Minute,
	}

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
		cfg := okCfg
		cfg.Alg = cred.AlgES256
		_, err := cred.LoadSignerFromMount(edPath, clk, cfg)
		if !errors.Is(err, cred.ErrSigningKeyInvalid) {
			t.Fatalf("wrong family: want ErrSigningKeyInvalid, got %v", err)
		}
	})

	t.Run("nonpositive-ttl", func(t *testing.T) {
		t.Parallel()
		cfg := okCfg
		cfg.StorageTTL = 0
		_, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgEdDSA), clk, cfg)
		if !errors.Is(err, cred.ErrConfig) {
			t.Fatalf("zero TTL: want ErrConfig, got %v", err)
		}
	})

	// The two unpinned-config subtests below are the W1 fail-closed guard. A
	// Storage-JWT minted with an empty iss or aud is UNPINNABLE at the trust edge:
	// the egress verifier pins both, so an empty claim is rejected there -- on live
	// traffic, per session, long after boot. Since the deployment supplies iss/aud
	// (they are never hardcoded here), an unset flag must abort at CONSTRUCTION, not
	// produce a custody core that mints tokens no verifier will accept. LoadSignerFromMount
	// is the only constructor of *Signer outside this package (its fields are
	// unexported) and cfg is never reassigned after it, so a *Signer that EXISTS is
	// provably pinned -- which is why the fence lives here and needs no mint-time twin.
	t.Run("empty-storage-issuer", func(t *testing.T) {
		t.Parallel()
		cfg := okCfg
		cfg.StorageIssuer = ""
		_, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgEdDSA), clk, cfg)
		if !errors.Is(err, cred.ErrConfig) {
			t.Fatalf("empty storage iss: want ErrConfig, got %v (an unpinnable token must never be mintable)", err)
		}
	})

	t.Run("empty-storage-audience", func(t *testing.T) {
		t.Parallel()
		cfg := okCfg
		cfg.StorageAudience = ""
		_, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgEdDSA), clk, cfg)
		if !errors.Is(err, cred.ErrConfig) {
			t.Fatalf("empty storage aud: want ErrConfig, got %v (an unpinnable token must never be mintable)", err)
		}
	})

	t.Run("es256-loads", func(t *testing.T) {
		t.Parallel()
		cfg := okCfg
		cfg.Alg = cred.AlgES256
		s, err := cred.LoadSignerFromMount(writeKeyMount(t, cred.AlgES256), clk, cfg)
		if err != nil {
			t.Fatalf("es256 load: %v", err)
		}
		if s.ActiveKID() == "" {
			t.Fatal("es256 signer has empty kid")
		}
	})
}

// TestMintedStorageJWTCarriesPinnedIssAud closes the loop the construction fence
// opens: a signer that loaded MUST put the configured iss/aud into the token body,
// because that is what the egress verifier pins on. The fence would be worthless if
// the mint dropped the claims on the floor. It asserts against the DECODED payload,
// not the struct, so a wire-name change (iss/aud) is caught too.
func TestMintedStorageJWTCarriesPinnedIssAud(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t, cred.AlgEdDSA, time.Minute)
	tok, err := signer.MintStorageJWT(context.Background(), cred.StorageMintReq{
		SessionKey:   "tenant/sess",
		FilesystemID: "fs-1",
		Authz:        cred.AuthorizationMetadata{Intent: cred.IntentRead},
	})
	if err != nil {
		t.Fatalf("MintStorageJWT: %v", err)
	}
	parts := strings.Split(tok.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("minted token is not a 3-part JWS: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var body struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	// newTestSigner's fixture values (helpers_test.go).
	if body.Iss != "https://control.example/provisional" {
		t.Errorf("minted iss = %q, want the configured issuer -- an empty or wrong iss is rejected by the pinning verifier at the edge", body.Iss)
	}
	if body.Aud != "egress.provisional" {
		t.Errorf("minted aud = %q, want the configured audience", body.Aud)
	}
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
