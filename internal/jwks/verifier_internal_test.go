// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestPublicKeyFromJWKRejectsMalformed covers the fail-closed reconstruction
// branches of publicKeyFromJWK: bad base64 in an OKP x, an OKP x of the wrong
// length, bad base64 in an EC x or y, and an unsupported kty/crv pair each fail
// rather than reconstruct a partial or wrong-curve key.
func TestPublicKeyFromJWKRejectsMalformed(t *testing.T) {
	t.Parallel()
	goodEC := freshECCoords(t)
	cases := []struct {
		name    string
		jwk     JWK
		wantErr error
	}{
		{"OKP bad base64 x", JWK{Kty: "OKP", Crv: "Ed25519", X: "!!!notbase64"}, ErrVerify},
		{"OKP wrong-length x", JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte("short"))}, ErrVerify},
		{"EC bad base64 x", JWK{Kty: "EC", Crv: "P-256", X: "!!!", Y: goodEC.y}, ErrVerify},
		{"EC bad base64 y", JWK{Kty: "EC", Crv: "P-256", X: goodEC.x, Y: "!!!"}, ErrVerify},
		{"unsupported kty/crv", JWK{Kty: "RSA", Crv: "P-521"}, ErrUnsupportedKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := publicKeyFromJWK(tc.jwk)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("publicKeyFromJWK(%s) = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestP256PublicKeyRejectsBadPoints covers p256PublicKey's fail-closed branches: a
// coordinate of the wrong octet length, and a syntactically-sized but off-curve
// point, are each ErrVerify — a forged JWK cannot reconstruct a key the parser
// would trust.
func TestP256PublicKeyRejectsBadPoints(t *testing.T) {
	t.Parallel()

	// Wrong-length coordinate.
	if _, err := p256PublicKey([]byte("short"), []byte("short")); !errors.Is(err, ErrVerify) {
		t.Fatalf("p256PublicKey(short) = %v, want ErrVerify", err)
	}

	// Correct length but not on the curve: all-zero x/y is the point at infinity /
	// off-curve, which the ECDH on-curve check rejects.
	zero := make([]byte, p256CoordLen)
	if _, err := p256PublicKey(zero, zero); !errors.Is(err, ErrVerify) {
		t.Fatalf("p256PublicKey(off-curve) = %v, want ErrVerify", err)
	}
}

// TestIntClaimReadsNumericForms covers intClaim's branches: a float64 (the JSON
// number form claims arrive as), a native int64, and a non-numeric value (which
// reads as the zero default rather than panicking).
func TestIntClaimReadsNumericForms(t *testing.T) {
	t.Parallel()
	m := jwt.MapClaims{
		"as_float": float64(1700000000),
		"as_int64": int64(42),
		"as_text":  "not a number",
	}
	if got := intClaim(m, "as_float"); got != 1700000000 {
		t.Errorf("intClaim(float64) = %d, want 1700000000", got)
	}
	if got := intClaim(m, "as_int64"); got != 42 {
		t.Errorf("intClaim(int64) = %d, want 42", got)
	}
	if got := intClaim(m, "as_text"); got != 0 {
		t.Errorf("intClaim(non-numeric) = %d, want 0 (default)", got)
	}
	if got := intClaim(m, "absent"); got != 0 {
		t.Errorf("intClaim(absent) = %d, want 0 (default)", got)
	}
}

// ecCoords holds base64url x/y for a real on-curve P-256 point, used to isolate the
// per-coordinate decode-error branches without also tripping the on-curve check.
type ecCoords struct{ x, y string }

func freshECCoords(t *testing.T) ecCoords {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdh key: %v", err)
	}
	// The ECDH public bytes are the uncompressed SEC1 point 0x04 || X(32) || Y(32),
	// the same encoding production reads, so the fixed-length coordinates come out
	// without touching the deprecated big.Int X/Y fields.
	raw := k.PublicKey().Bytes()
	return ecCoords{
		x: base64.RawURLEncoding.EncodeToString(raw[1 : 1+p256CoordLen]),
		y: base64.RawURLEncoding.EncodeToString(raw[1+p256CoordLen:]),
	}
}
