// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// TestLoadExecSignerFromMount pins the boot-time loader: a valid PKCS8 PEM Ed25519
// key loads and its VerifyKey matches the key's public half; a missing file and a
// non-PKCS8 blob each fail closed (the fail-closed boot the daemon relies on).
func TestLoadExecSignerFromMount(t *testing.T) {
	t.Parallel()

	t.Run("valid pkcs8 pem loads and verify-key matches", func(t *testing.T) {
		t.Parallel()
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		path := filepath.Join(t.TempDir(), "exec-signing.key")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		s, err := cred.LoadExecSignerFromMount(path)
		if err != nil {
			t.Fatalf("LoadExecSignerFromMount: %v", err)
		}
		if !s.VerifyKey().Equal(pub) {
			t.Fatal("VerifyKey does not match the loaded key's public half")
		}
		tok, err := s.MintExecJWT(context.Background(), cred.ExecMintReq{ContainerName: "c", RequestedTTL: time.Minute})
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if tok.IsZero() {
			t.Fatal("minted token is zero")
		}
	})

	t.Run("missing file fails closed", func(t *testing.T) {
		t.Parallel()
		if _, err := cred.LoadExecSignerFromMount(filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("LoadExecSignerFromMount on a missing file = nil error; want fail-closed")
		}
	})

	t.Run("non-pkcs8 blob fails closed", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "garbage.key")
		if err := os.WriteFile(path, []byte("not a pkcs8 key"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := cred.LoadExecSignerFromMount(path); err == nil {
			t.Fatal("LoadExecSignerFromMount on a non-PKCS8 blob = nil error; want fail-closed")
		}
	})
}

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
