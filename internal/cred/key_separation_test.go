// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// verifyEdDSAJWT reports whether a compact EdDSA JWS verifies under pub. It is a
// minimal detached-signature check (the same shape the guest's verifier and the
// Egress trust-edge's JWKS validation use): the signature over
// base64url(header).base64url(claims) must verify under pub.
func verifyEdDSAJWT(t *testing.T, compact string, pub ed25519.PublicKey) bool {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	return ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig)
}

// storagePub extracts the active storage signing key's Ed25519 public half — the
// key the JWKS publishes and the Egress trust-edge validates the weak Storage-JWT
// against.
func storagePub(t *testing.T, s *cred.Signer) ed25519.PublicKey {
	t.Helper()
	keys := s.PublicKeys()
	if len(keys) == 0 {
		t.Fatal("storage signer published no public keys")
	}
	pub, ok := keys[0].Pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("storage public key is %T, want ed25519.PublicKey", keys[0].Pub)
	}
	return pub
}

// TestExecAndStorageKeysAreSeparate is the custody keystone (ADR-0013 key
// separation): the exec-channel key and the Storage-JWT keyring NEVER share
// material. An exec-JWT must NOT verify under the storage/JWKS public key, and a
// storage-JWT must NOT verify under the exec verify-key. If a refactor ever routed
// both mints through one key (the bug the live exec surfaced), the cross-checks
// below would BOTH pass and this test would fail — so it is the standing guard that
// the two custody planes stay disjoint.
func TestExecAndStorageKeysAreSeparate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storageSigner, _ := newTestSigner(t, cred.AlgEdDSA, 10*time.Minute)
	execSigner, execPub := newTestExecSigner(t)

	storageTok, err := storageSigner.MintStorageJWT(ctx, cred.StorageMintReq{
		FilesystemID: "fs-sep",
		Authz:        cred.AuthorizationMetadata{Intent: cred.IntentRead},
	})
	if err != nil {
		t.Fatalf("MintStorageJWT: %v", err)
	}
	execTok, err := execSigner.MintExecJWT(ctx, cred.ExecMintReq{
		ContainerName: "ocu-sess-sep",
		RequestedTTL:  time.Minute,
	})
	if err != nil {
		t.Fatalf("MintExecJWT: %v", err)
	}

	stPub := storagePub(t, storageSigner)

	// Each token verifies under its OWN key (sanity — the keys work).
	if !verifyEdDSAJWT(t, execTok.Reveal(), execPub) {
		t.Fatal("exec token does not verify under the exec verify-key (its own key)")
	}
	if !verifyEdDSAJWT(t, storageTok.Reveal(), stPub) {
		t.Fatal("storage token does not verify under the storage JWKS key (its own key)")
	}

	// KEY SEPARATION: neither token verifies under the OTHER plane's key.
	if verifyEdDSAJWT(t, execTok.Reveal(), stPub) {
		t.Fatal("exec token verifies under the storage/JWKS key — the keys are shared (ADR-0013 violation)")
	}
	if verifyEdDSAJWT(t, storageTok.Reveal(), execPub) {
		t.Fatal("storage token verifies under the exec verify-key — the keys are shared (ADR-0013 violation)")
	}
}
