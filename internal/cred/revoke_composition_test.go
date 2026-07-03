// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/runtime"
)

// TestMintThenRevokeRealComposition drives the WHOLE shipped chain end to end:
// a real Signer.MintStorageJWT (which records the jti via the production
// signer.go Record(req.SessionKey, jti) call) followed by a Revoke keyed off the
// EgressBinding.Name the finalizer holds — NOT a hand-recorded jti. This is the
// composition the fake-green revoke tests never exercised: they hand-called
// Record under a key they chose, mirroring the shared-key assumption instead of
// driving the real mint. If the mint's record key and the revoke's lookup key
// disagree (the key-drift regression this PR closes), the revoke returns
// none_bound and this test fails — so it pins the mint→record→revoke chain
// through the shipped signer, not a mirror of it.
func TestMintThenRevokeRealComposition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	signer, clk := newTestSigner(t, cred.AlgEdDSA, time.Minute)
	revoker := cred.NewRevoker(clk)
	signer.UseRevoker(revoker)

	// The host-derived session key the create path passes as SessionKey (== row.Key).
	// A low-entropy, obviously-non-secret literal: the generic-api-key detector
	// flags a high-entropy string assigned to a *Key-named const as a possible
	// credential, so keep the value plainly human words.
	const sessionKey = "test session key alpha"

	if _, err := signer.MintStorageJWT(ctx, cred.StorageMintReq{
		SessionKey:   sessionKey,
		FilesystemID: "mount-fs-id", // deliberately DIFFERENT from the session key
		Workspace:    "ws",
		Org:          "org",
		Authz:        cred.AuthorizationMetadata{Intent: cred.IntentWrite},
	}); err != nil {
		t.Fatalf("MintStorageJWT: %v", err)
	}

	// Now revoke exactly as the finalizer does: off the EgressBinding whose Name
	// is the host-derived session identity (SessionName(row.Key)). The FilesystemID
	// on the binding is the mount scope, NOT the revoke key.
	outcome, err := revoker.Revoke(ctx, runtime.EgressBinding{
		Name:         runtime.SessionName(sessionKey),
		FilesystemID: "mount-fs-id",
	})
	if err != nil {
		t.Fatalf("Revoke after a real mint: got %v — the mint's record key and the revoke's lookup key disagree (key drift)", err)
	}
	// RevokeMarkedDead can only be reached if the revoke lookup found the jti the
	// REAL mint recorded — i.e. the record key and the lookup key agree by
	// construction (BindKey). A key drift would surface as RevokeNoneBound here.
	if outcome != runtime.RevokeMarkedDead {
		t.Fatalf("outcome = %v, want RevokeMarkedDead — the real mint recorded a jti the revoke must mark dead (a drift would read none_bound)", outcome)
	}
}
