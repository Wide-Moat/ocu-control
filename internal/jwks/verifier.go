// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

// ErrVerify is the wrapping sentinel for any signature, structure, or exp
// failure surfaced by the underlying JWS parse. A caller distinguishes a missing
// key (ErrNoMatchingKID) and a revocation (ErrRevoked) from a generic
// verification failure (ErrVerify), without leaking the token bytes.
var ErrVerify = errors.New("jwks: token failed verification")

// nowFunc supplies the current instant the Verifier honors exp against. It is the
// injected monotonic Clock's Now in production wiring, so an Advance past exp
// makes a token fail — the same Clock seam the Signer mints against. A nil
// nowFunc falls back to the real wall clock.
type nowFunc func() time.Time

// Verifier stands in for the egress trust-edge's validation of the weak
// Storage-JWT. It holds ONLY the published public keys: it matches a token's kid
// against the set, verifies the JWS signature with the selected key, HONORS exp
// against the injected now (an expired token after an Advance does NOT verify),
// and consults an optional revocation predicate so a revoked jti fails even with
// a still-future exp. It does NOT hard-assert a literal iss/aud: those are
// config-driven and provisional (PIN-PENDING a later contract pin), so baking a
// value into the stand-in would break at the pin. The Verifier holds no private
// material and speaks no network protocol.
type Verifier struct {
	set     Set
	now     nowFunc
	revoked func(jti string) bool // optional; nil => no revocation check
}

// NewVerifier builds a Verifier over a published Set. now supplies the instant
// exp is honored against (pass the injected Clock's Now so the stand-in shares
// the Signer's monotonic timeline); a nil now falls back to the real wall clock.
// revoked is the optional revocation predicate (pass cred.Revoker.IsRevoked to
// wire the monotonic revocation index); a nil revoked disables the revocation
// check.
func NewVerifier(set Set, now func() time.Time, revoked func(jti string) bool) *Verifier {
	return &Verifier{set: set, now: now, revoked: revoked}
}

// Verify parses and validates a compact Storage-JWT against the published set.
// It selects the key by the token's kid header (ErrNoMatchingKID if none
// matches), verifies the signature and exp with golang-jwt against the injected
// now, then consults the revocation predicate (ErrRevoked if the jti is dead).
// On success it returns the typed StorageClaims. The token bytes are never put
// into an error; a failure wraps ErrVerify with the library's structural reason,
// never the compact JWT.
func (v *Verifier) Verify(compact string) (cred.StorageClaims, error) {
	timeFunc := time.Now
	if v.now != nil {
		timeFunc = v.now
	}

	parsed, err := jwt.Parse(
		compact,
		v.keyFunc,
		jwt.WithValidMethods([]string{cred.AlgEdDSA.JWTMethod(), cred.AlgES256.JWTMethod()}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(timeFunc),
	)
	if err != nil {
		if errors.Is(err, errNoMatchingKID) {
			return cred.StorageClaims{}, ErrNoMatchingKID
		}
		return cred.StorageClaims{}, fmt.Errorf("%w: %v", ErrVerify, err)
	}

	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return cred.StorageClaims{}, fmt.Errorf("%w: unexpected claims shape", ErrVerify)
	}
	claims := storageClaimsFromMap(mapClaims)

	if v.revoked != nil && claims.JTI != "" && v.revoked(claims.JTI) {
		return cred.StorageClaims{}, ErrRevoked
	}
	return claims, nil
}

// errNoMatchingKID is the internal sentinel the keyFunc returns when a token's
// kid names no published key; Verify maps it to the exported ErrNoMatchingKID.
// It is kept internal so the keyFunc and Verify agree without exposing a second
// public symbol.
var errNoMatchingKID = errors.New("jwks: keyfunc found no matching kid")

// keyFunc selects the verification key for a parsed token from its kid header.
// It returns the reconstructed public key (ed25519.PublicKey or *ecdsa.PublicKey)
// for the matching JWK, or errNoMatchingKID if the kid matches nothing in the
// published set. A token without a kid header (or with a non-string kid) matches
// nothing, which is the safe fail-closed outcome.
func (v *Verifier) keyFunc(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, errNoMatchingKID
	}
	for _, jwk := range v.set.Keys {
		if jwk.Kid != kid {
			continue
		}
		return publicKeyFromJWK(jwk)
	}
	return nil, errNoMatchingKID
}

// publicKeyFromJWK reconstructs the crypto public key from a published JWK,
// selecting the family by kty/crv. A malformed coordinate or an unexpected curve
// is an error so the parse fails closed rather than verifying against a partial
// key.
func publicKeyFromJWK(jwk JWK) (any, error) {
	switch {
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519":
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("%w: decode OKP x: %v", ErrVerify, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: OKP x is not an ed25519 public key", ErrVerify)
		}
		return ed25519.PublicKey(raw), nil
	case jwk.Kty == "EC" && jwk.Crv == "P-256":
		xRaw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("%w: decode EC x: %v", ErrVerify, err)
		}
		yRaw, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("%w: decode EC y: %v", ErrVerify, err)
		}
		return p256PublicKey(xRaw, yRaw)
	default:
		return nil, fmt.Errorf("%w: kty %q crv %q", ErrUnsupportedKey, jwk.Kty, jwk.Crv)
	}
}

// p256PublicKey reconstructs and on-curve-validates a P-256 public key from its
// raw x/y coordinates. It validates via the non-deprecated crypto/ecdh path
// (NewPublicKey rejects an off-curve point and the point at infinity), then
// builds the *ecdsa.PublicKey golang-jwt's ES256 method verifies against. A
// malformed or off-curve point is a hard ErrVerify, so a forged JWK can never
// reconstruct a key the parser would trust.
func p256PublicKey(x, y []byte) (any, error) {
	if len(x) != p256CoordLen || len(y) != p256CoordLen {
		return nil, fmt.Errorf("%w: EC coordinate is not %d octets", ErrVerify, p256CoordLen)
	}
	// Uncompressed SEC1 point: 0x04 || X || Y. NewPublicKey performs the on-curve
	// check, replacing the deprecated elliptic.IsOnCurve.
	sec1 := make([]byte, 0, 1+2*p256CoordLen)
	sec1 = append(sec1, 0x04)
	sec1 = append(sec1, x...)
	sec1 = append(sec1, y...)
	if _, err := ecdh.P256().NewPublicKey(sec1); err != nil {
		return nil, fmt.Errorf("%w: EC point is not on P-256: %v", ErrVerify, err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

// storageClaimsFromMap projects the verified MapClaims back into the typed
// StorageClaims the egress edge keys on. Missing or wrong-typed members decode to
// their zero value rather than failing, since the signature and exp checks (the
// authority) already passed; the typed projection is for the caller's
// convenience, not a second validation gate.
func storageClaimsFromMap(m jwt.MapClaims) cred.StorageClaims {
	claims := cred.StorageClaims{
		Issuer:       stringClaim(m, "iss"),
		Audience:     stringClaim(m, "aud"),
		FilesystemID: stringClaim(m, "filesystem_id"),
		Workspace:    stringClaim(m, "workspace"),
		Org:          stringClaim(m, "org"),
		IssuedAtUnix: intClaim(m, "iat"),
		ExpiryUnix:   intClaim(m, "exp"),
		JTI:          stringClaim(m, "jti"),
	}
	if authz, ok := m["authz"].(map[string]any); ok {
		claims.Authz = cred.AuthorizationMetadata{
			Scope:        stringFromMap(authz, "scope"),
			Intent:       cred.Intent(stringFromMap(authz, "intent")),
			Downloadable: boolFromMap(authz, "downloadable"),
		}
	}
	return claims
}

func stringClaim(m jwt.MapClaims, k string) string { return stringFromMap(m, k) }

func stringFromMap(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func boolFromMap(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

// intClaim reads a numeric JWT claim. JSON numbers decode to float64 through the
// generic map, so iat/exp arrive as float64; the conversion is exact for the
// 53-bit-safe unix-second range these claims occupy.
func intClaim(m jwt.MapClaims, k string) int64 {
	switch n := m[k].(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	default:
		return 0
	}
}
