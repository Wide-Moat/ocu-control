// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// TestExecSignerMintsGuestVerifiableJWT pins the exec-JWT contract the guest
// verifies: a compact EdDSA JWS whose claims are EXACTLY {sub,iat,exp} (no aud, no
// iss — an aud:"" claim trips the guest's audience validation, which is what killed
// the live exec), sub == the container name, and the signature verifies under the
// exec verify-key's public half.
func TestExecSignerMintsGuestVerifiableJWT(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	s := cred.NewExecSigner(priv)

	tok, err := s.MintExecJWT(context.Background(), cred.ExecMintReq{
		ContainerName: "ocu-sess-abc",
		RequestedTTL:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("MintExecJWT: %v", err)
	}
	raw := tok.Reveal()

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts; want 3", len(parts))
	}
	// Header: EdDSA, no kid.
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr["alg"] != "EdDSA" {
		t.Fatalf("alg = %v; want EdDSA", hdr["alg"])
	}
	if _, present := hdr["kid"]; present {
		t.Fatal("exec JWT header carries a kid; the guest verifies a keyless EdDSA JWS")
	}
	// Claims: EXACTLY {sub,iat,exp}, sub == container name, NO aud/iss.
	clJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(clJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims["sub"] != "ocu-sess-abc" {
		t.Fatalf("sub = %v; want the container name", claims["sub"])
	}
	for _, forbidden := range []string{"aud", "iss"} {
		if _, present := claims[forbidden]; present {
			t.Fatalf("exec JWT claims carry %q; the guest rejects any aud/iss (must be {sub,iat,exp} only)", forbidden)
		}
	}
	if _, ok := claims["iat"]; !ok {
		t.Fatal("exec JWT missing iat")
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatal("exec JWT missing exp")
	}
	// Signature verifies under the exec verify-key's public half.
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		t.Fatal("exec JWT signature does not verify under the exec public key")
	}
}

// TestExecSignerRefusesEmptyContainerName pins the identity precondition: an unbound
// exec JWT must be unrepresentable.
func TestExecSignerRefusesEmptyContainerName(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := cred.NewExecSigner(priv)
	if _, err := s.MintExecJWT(context.Background(), cred.ExecMintReq{ContainerName: ""}); !errors.Is(err, cred.ErrMintIdentity) {
		t.Fatalf("MintExecJWT with empty container_name = %v; want ErrMintIdentity", err)
	}
}

// TestExecSignerRedactsToken pins custody: the minted exec Token redacts on every
// emit surface, exactly like the storage Token — the raw JWT is reachable only
// through Reveal.
func TestExecSignerRedactsToken(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := cred.NewExecSigner(priv).MintExecJWT(context.Background(), cred.ExecMintReq{
		ContainerName: "c", RequestedTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("MintExecJWT: %v", err)
	}
	if got := tok.String(); strings.Contains(got, ".") || got == tok.Reveal() {
		t.Fatalf("String() = %q leaks the raw JWT; want the redaction sentinel", got)
	}
}
