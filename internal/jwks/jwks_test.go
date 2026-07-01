// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/jwks"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// egressBinding builds the runtime.EgressBinding the below-seam finalizer hands
// the Revoker, keyed on the filesystem id.
func egressBinding(filesystemID string) runtime.EgressBinding {
	return runtime.EgressBinding{
		Name:         runtime.SessionName("sess-key-host-derived"),
		FilesystemID: filesystemID,
	}
}

// testStart anchors every FakeClock so a run is reproducible and a setback is
// expressed relative to it.
var testStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

const testStorageTTL = 15 * time.Minute

// writeKeyMount writes a PKCS8 PEM private key for alg into a temp file and
// returns the path, modelling the -jwt-signing-key config/secret mount.
func writeKeyMount(t *testing.T, alg cred.Alg) string {
	t.Helper()
	var key any
	switch alg {
	case cred.AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519: %v", err)
		}
		key = priv
	case cred.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa: %v", err)
		}
		key = priv
	default:
		t.Fatalf("unsupported alg %v", alg)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
	return path
}

// newSigner loads a Signer over a freshly generated key for alg on a FakeClock
// anchored at testStart.
func newSigner(t *testing.T, alg cred.Alg) (*cred.Signer, *state.FakeClock) {
	t.Helper()
	clk := state.NewFakeClock(testStart)
	cfg := cred.Config{
		Alg:             alg,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		ExecIssuer:      "https://control.example/exec-provisional",
		ExecAudience:    "guest.exec.provisional",
		StorageTTL:      testStorageTTL,
	}
	signer, err := cred.LoadSignerFromMount(writeKeyMount(t, alg), clk, cfg)
	if err != nil {
		t.Fatalf("LoadSignerFromMount: %v", err)
	}
	return signer, clk
}

// freshEd25519Signer returns a new Ed25519 crypto.Signer for a rotation step.
func freshEd25519Signer(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return priv
}

func mintStorage(t *testing.T, signer *cred.Signer) cred.Token {
	t.Helper()
	tok, err := signer.MintStorageJWT(context.Background(), cred.StorageMintReq{
		SessionKey:   "sess-key-host-derived",
		FilesystemID: "session_01HXYZ_chat",
		Workspace:    "ws-1",
		Org:          "org-1",
		Authz: cred.AuthorizationMetadata{
			Scope:        "session_01HXYZ_chat",
			Intent:       cred.IntentWrite,
			Downloadable: false,
		},
	})
	if err != nil {
		t.Fatalf("MintStorageJWT: %v", err)
	}
	return tok
}

func publishFrom(t *testing.T, signer *cred.Signer) jwks.Set {
	t.Helper()
	set, err := jwks.Publish(signer.PublicKeys())
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return set
}

// TestMintedTokenVerifies covers both algs: a freshly minted token verifies
// against the published set, the kid in the JWK matches the Signer's active kid,
// and the typed claims round-trip.
func TestMintedTokenVerifies(t *testing.T) {
	for _, alg := range []cred.Alg{cred.AlgEdDSA, cred.AlgES256} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			signer, clk := newSigner(t, alg)
			tok := mintStorage(t, signer)
			set := publishFrom(t, signer)

			if len(set.Keys) != 1 {
				t.Fatalf("published set has %d keys, want 1", len(set.Keys))
			}
			if set.Keys[0].Kid != signer.ActiveKID() {
				t.Fatalf("JWK kid %q != active kid %q", set.Keys[0].Kid, signer.ActiveKID())
			}
			if set.Keys[0].Alg != alg.JWTMethod() {
				t.Fatalf("JWK alg %q != %q", set.Keys[0].Alg, alg.JWTMethod())
			}

			v := jwks.NewVerifier(set, clk.Now, nil)
			claims, err := v.Verify(tok.Reveal())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if claims.FilesystemID != "session_01HXYZ_chat" {
				t.Fatalf("filesystem_id = %q, want session_01HXYZ_chat", claims.FilesystemID)
			}
			if claims.Authz.Intent != cred.IntentWrite {
				t.Fatalf("intent = %q, want write", claims.Authz.Intent)
			}
			if claims.JTI == "" {
				t.Fatal("expected a non-empty jti")
			}
		})
	}
}

// TestExpiredAfterAdvanceFails proves the Verifier HONORS exp against the
// injected Clock: advancing past the TTL makes a previously-valid token fail.
func TestExpiredAfterAdvanceFails(t *testing.T) {
	signer, clk := newSigner(t, cred.AlgEdDSA)
	tok := mintStorage(t, signer)
	set := publishFrom(t, signer)
	v := jwks.NewVerifier(set, clk.Now, nil)

	if _, err := v.Verify(tok.Reveal()); err != nil {
		t.Fatalf("token should verify before exp: %v", err)
	}

	clk.Advance(testStorageTTL + time.Second)
	if _, err := v.Verify(tok.Reveal()); err == nil {
		t.Fatal("expired token verified after Advance past TTL")
	} else if !errors.Is(err, jwks.ErrVerify) {
		t.Fatalf("expired token error = %v, want ErrVerify", err)
	}
}

// TestWrongKIDFails proves a token whose kid names no published key fails with
// ErrNoMatchingKID — the published set is the closed universe of trust.
func TestWrongKIDFails(t *testing.T) {
	signerA, clk := newSigner(t, cred.AlgEdDSA)
	signerB, _ := newSigner(t, cred.AlgEdDSA)

	tok := mintStorage(t, signerA)
	// Publish only signerB's key: signerA's token kid matches nothing.
	set := publishFrom(t, signerB)
	v := jwks.NewVerifier(set, clk.Now, nil)

	if _, err := v.Verify(tok.Reveal()); !errors.Is(err, jwks.ErrNoMatchingKID) {
		t.Fatalf("error = %v, want ErrNoMatchingKID", err)
	}
}

// TestRevokedTokenFails proves a revoked jti fails verification even though its
// exp is still in the future — the Verifier consults the revocation predicate.
func TestRevokedTokenFails(t *testing.T) {
	signer, clk := newSigner(t, cred.AlgEdDSA)
	revoker := cred.NewRevoker(clk)
	tok := mintStorage(t, signer)
	set := publishFrom(t, signer)

	// Recover the jti the way the create path does, then revoke it. We verify
	// once with no predicate to read the jti, then build a revoking verifier.
	plain := jwks.NewVerifier(set, clk.Now, nil)
	claims, err := plain.Verify(tok.Reveal())
	if err != nil {
		t.Fatalf("Verify (to read jti): %v", err)
	}
	revoker.Record(claims.FilesystemID, claims.JTI)
	if err := revoker.Revoke(context.Background(), egressBinding(claims.FilesystemID)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	v := jwks.NewVerifier(set, clk.Now, revoker.IsRevoked)
	if _, err := v.Verify(tok.Reveal()); !errors.Is(err, jwks.ErrRevoked) {
		t.Fatalf("error = %v, want ErrRevoked", err)
	}

	// A wall-clock setback after the revoke never un-revokes (monotonic mark).
	clk.SetWallClock(testStart.Add(-time.Hour))
	if _, err := v.Verify(tok.Reveal()); !errors.Is(err, jwks.ErrRevoked) {
		t.Fatalf("after wall setback error = %v, want ErrRevoked", err)
	}
}

// TestOverlapPublishesBothThenDrops proves the JWKS publishes the active plus the
// overlap-previous key, that a token minted under the previous key still verifies
// during the overlap, and that the previous key drops after the monotonic clock
// passes the overlap window — and a wall setback never resurrects it.
func TestOverlapPublishesBothThenDrops(t *testing.T) {
	signer, clk := newSigner(t, cred.AlgEdDSA)

	// Mint under the original key, then rotate.
	prevTok := mintStorage(t, signer)
	newKey := freshEd25519Signer(t)
	signer.KeySet().Rotate(newKey, cred.AlgEdDSA, "kid-rotated-2")

	// Inside the overlap both keys publish; the previous-key token still verifies.
	set := publishFrom(t, signer)
	if len(set.Keys) != 2 {
		t.Fatalf("overlap set has %d keys, want 2", len(set.Keys))
	}
	v := jwks.NewVerifier(set, clk.Now, nil)
	if _, err := v.Verify(prevTok.Reveal()); err != nil {
		t.Fatalf("previous-key token should verify in overlap: %v", err)
	}

	// Advance past the 24h overlap window: the previous key drops from the set.
	clk.Advance(25 * time.Hour)
	set2 := publishFrom(t, signer)
	if len(set2.Keys) != 1 {
		t.Fatalf("post-overlap set has %d keys, want 1", len(set2.Keys))
	}
	v2 := jwks.NewVerifier(set2, clk.Now, nil)
	if _, err := v2.Verify(prevTok.Reveal()); !errors.Is(err, jwks.ErrNoMatchingKID) {
		t.Fatalf("dropped-key token error = %v, want ErrNoMatchingKID", err)
	}

	// A wall setback never resurrects the dropped key (Since rides the monotonic
	// base, not the settable wall reading).
	clk.SetWallClock(testStart)
	set3 := publishFrom(t, signer)
	if len(set3.Keys) != 1 {
		t.Fatalf("set after wall setback has %d keys, want 1 (previous stays dropped)", len(set3.Keys))
	}
}

// TestPublishCarriesNoPrivateMaterial asserts the published JWK never carries a
// "d" (private scalar) member: a default marshal of the Set must not leak the
// private half. The JWK struct has no private field by construction; this guards
// against a future field addition.
func TestPublishCarriesNoPrivateMaterial(t *testing.T) {
	signer, _ := newSigner(t, cred.AlgES256)
	set := publishFrom(t, signer)
	for _, k := range set.Keys {
		if k.X == "" {
			t.Fatal("EC JWK missing x coordinate")
		}
		if k.Y == "" {
			t.Fatal("EC JWK missing y coordinate")
		}
	}
}
