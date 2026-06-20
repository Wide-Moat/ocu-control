// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestAlgJWKParameters covers the JWK crv/kty/method accessors for both supported
// algorithms and the unknown-alg fall-through, so a JWKS publisher reading these
// renders the correct EdDSA/OKP/Ed25519 and ES256/EC/P-256 triples and never a
// silent default for an out-of-range value.
func TestAlgJWKParameters(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		alg              cred.Alg
		method, crv, kty string
		valid            bool
		str              string
	}{
		{"EdDSA", cred.AlgEdDSA, "EdDSA", "Ed25519", "OKP", true, "EdDSA"},
		{"ES256", cred.AlgES256, "ES256", "P-256", "EC", true, "ES256"},
		// An out-of-range Alg resolves to empty JWK parameters and the bracketed
		// sentinel String, and is not Valid — the fail-closed posture a publisher checks.
		{"unknown", cred.Alg(99), "", "", "", false, "Alg(unknown)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.alg.JWTMethod(); got != tc.method {
				t.Errorf("JWTMethod() = %q, want %q", got, tc.method)
			}
			if got := tc.alg.JWKCrv(); got != tc.crv {
				t.Errorf("JWKCrv() = %q, want %q", got, tc.crv)
			}
			if got := tc.alg.JWKKty(); got != tc.kty {
				t.Errorf("JWKKty() = %q, want %q", got, tc.kty)
			}
			if got := tc.alg.Valid(); got != tc.valid {
				t.Errorf("Valid() = %v, want %v", got, tc.valid)
			}
			if got := tc.alg.String(); got != tc.str {
				t.Errorf("String() = %q, want %q", got, tc.str)
			}
		})
	}
}

// TestSignerPublicKeysAndStorageTTL covers the JWKS-facing PublicKeys accessor and
// the StorageTTL preview accessor: a freshly loaded signer publishes exactly its one
// active public key (carrying the active kid and the configured alg) and reports the
// configured TTL without minting.
func TestSignerPublicKeysAndStorageTTL(t *testing.T) {
	t.Parallel()
	const ttl = 17 * time.Minute
	signer, _ := newTestSigner(t, cred.AlgEdDSA, ttl)

	keys := signer.PublicKeys()
	if len(keys) != 1 {
		t.Fatalf("PublicKeys() len = %d, want 1 active key for a fresh signer", len(keys))
	}
	if keys[0].KID != signer.ActiveKID() {
		t.Errorf("published kid = %q, want active kid %q", keys[0].KID, signer.ActiveKID())
	}
	if keys[0].Alg != cred.AlgEdDSA {
		t.Errorf("published alg = %v, want AlgEdDSA", keys[0].Alg)
	}
	if got := signer.StorageTTL(); got != ttl {
		t.Errorf("StorageTTL() = %v, want %v", got, ttl)
	}
}

// TestUseRevokerNilIsNoOp covers the nil-Revoker branch of UseRevoker: passing nil
// must not panic and must leave the signer minting normally (the Phase-3 minimal
// shelf has no revoker bound).
func TestUseRevokerNilIsNoOp(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t, cred.AlgEdDSA, time.Minute)
	signer.UseRevoker(nil) // must not panic

	if _, err := signer.MintExecJWT(t.Context(), cred.ExecMintReq{
		ContainerName: "ctr-nil-revoker",
		RequestedTTL:  time.Minute,
	}); err != nil {
		t.Fatalf("MintExecJWT after UseRevoker(nil) = %v, want nil (mint still works)", err)
	}
}

// TestNewRevokerNilClockFallsBackToSystemClock covers the nil-clock branch of
// NewRevoker: a nil clock falls back to the system clock rather than panicking, and
// the resulting revoker records and revokes a binding normally.
func TestNewRevokerNilClockFallsBackToSystemClock(t *testing.T) {
	t.Parallel()
	r := cred.NewRevoker(nil) // nil clock must fall back, not panic
	const fsID = "fs-nil-clock"
	const jti = "jti-nil-clock"
	r.Record(fsID, jti)
	if err := r.Revoke(context.Background(), runtime.EgressBinding{FilesystemID: fsID}); err != nil {
		t.Fatalf("Revoke on system-clock revoker = %v, want nil", err)
	}
	if !r.IsRevoked(jti) {
		t.Fatal("jti must be revoked after Revoke on a nil-clock revoker")
	}
}

// TestMintRefusesCancelledContext covers the fail-closed ctx.Err() guard on both
// mint paths: a cancelled context refuses the mint before any signing, so a dropped
// caller never yields a signed token.
func TestMintRefusesCancelledContext(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t, cred.AlgEdDSA, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := signer.MintStorageJWT(ctx, cred.StorageMintReq{
		FilesystemID: "fs-1",
		Authz:        cred.AuthorizationMetadata{Intent: cred.IntentRead},
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("MintStorageJWT cancelled = %v, want context.Canceled", err)
	}
	if _, err := signer.MintExecJWT(ctx, cred.ExecMintReq{ContainerName: "ctr-1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("MintExecJWT cancelled = %v, want context.Canceled", err)
	}
}
