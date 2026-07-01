// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package jwks publishes the JSON Web Key Set the egress trust-edge validates
// the weak Storage-JWT against, and provides a stand-in Verifier that models the
// edge's validation (kid match, signature, exp, revocation). Control holds the
// signing key in internal/cred and publishes ONLY the public halves here: this
// package never sees private material. The Verifier is a Control-side stand-in
// for the real egress edge (which is out of scope for the control plane), used
// to prove the round-trip — a minted token verifies against the published set,
// an expired token does not, and a revoked jti does not.
package jwks

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Wide-Moat/ocu-control/internal/cred"
)

var (
	// ErrNoMatchingKID is returned by the Verifier when a token's kid header names
	// no key in the published set (a key that has rotated fully out of the overlap
	// window, or a forged kid).
	ErrNoMatchingKID = errors.New("jwks: no published key for token kid")
	// ErrRevoked is returned by the Verifier when a token's jti is marked revoked
	// by the consulted revocation predicate, even if its exp is still in the
	// future.
	ErrRevoked = errors.New("jwks: token jti is revoked")
	// ErrUnsupportedKey is returned by Publish when a PublicKey carries an Alg or a
	// concrete key type it cannot render into a JWK. It is fail-closed: a key it
	// cannot publish is never silently dropped from the set.
	ErrUnsupportedKey = errors.New("jwks: cannot publish key of unsupported alg or type")
)

// JWK is one public key in JWK form. kty/crv/alg follow the key's cred.Alg
// (OKP/Ed25519/EdDSA or EC/P-256/ES256); kid matches the kid the Signer stamped
// on the minted tokens, so the Verifier can select the right key by header. Use
// is always "sig". The coordinates are unpadded base64url per RFC 7518.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"` // EC only; absent for OKP/Ed25519
}

// Set is the published JWKS document: the active key plus, during the rotation
// overlap, the just-superseded key. It carries no private material.
type Set struct {
	Keys []JWK `json:"keys"`
}

// Publish renders the JWKS from the Signer's current public keys (active plus the
// overlap-previous key while it is still within the window). It carries NO
// private material: each cred.PublicKey holds only the public half. A key whose
// Alg or concrete type it cannot render is a hard ErrUnsupportedKey, never a
// silent omission, so the published set can never be missing a key a live token
// was minted under.
func Publish(pub []cred.PublicKey) (Set, error) {
	keys := make([]JWK, 0, len(pub))
	for _, p := range pub {
		jwk, err := toJWK(p)
		if err != nil {
			return Set{}, err
		}
		keys = append(keys, jwk)
	}
	return Set{Keys: keys}, nil
}

// toJWK renders one public key into its JWK form, selecting the JWK members from
// the key's cred.Alg and asserting the concrete key type matches. A mismatch
// (an EC key tagged EdDSA, or an unknown alg) is ErrUnsupportedKey.
func toJWK(p cred.PublicKey) (JWK, error) {
	if !p.Alg.Valid() {
		return JWK{}, fmt.Errorf("%w: alg %v", ErrUnsupportedKey, p.Alg)
	}
	base := JWK{
		Kty: p.Alg.JWKKty(),
		Crv: p.Alg.JWKCrv(),
		Kid: p.KID,
		Use: "sig",
		Alg: p.Alg.JWTMethod(),
	}
	switch p.Alg {
	case cred.AlgEdDSA:
		edPub, ok := p.Pub.(ed25519.PublicKey)
		if !ok {
			return JWK{}, fmt.Errorf("%w: alg EdDSA with non-ed25519 key", ErrUnsupportedKey)
		}
		base.X = base64.RawURLEncoding.EncodeToString(edPub)
		return base, nil
	case cred.AlgES256:
		ecPub, ok := p.Pub.(*ecdsa.PublicKey)
		if !ok {
			return JWK{}, fmt.Errorf("%w: alg ES256 with non-ecdsa key", ErrUnsupportedKey)
		}
		x, y, err := p256Coords(ecPub)
		if err != nil {
			return JWK{}, err
		}
		base.X = base64.RawURLEncoding.EncodeToString(x)
		base.Y = base64.RawURLEncoding.EncodeToString(y)
		return base, nil
	default:
		return JWK{}, fmt.Errorf("%w: alg %v", ErrUnsupportedKey, p.Alg)
	}
}

// p256CoordLen is the fixed octet length of a P-256 field element (256 bits). The
// uncompressed SEC1 point the ecdh encoding yields is 0x04 followed by two
// fixed-length, left-padded coordinates, so JWK x/y are exact 32-octet slices —
// no manual big.Int padding, and no use of the deprecated raw-coordinate fields.
const p256CoordLen = 32

// p256Coords returns the fixed-length X and Y coordinates of a P-256 public key,
// via the non-deprecated ecdh encoding (0x04 || X || Y). It fails closed if the
// key cannot be represented as an ECDH point (e.g. the point at infinity), so a
// JWK is never published from an unusable key.
func p256Coords(pub *ecdsa.PublicKey) (x, y []byte, err error) {
	ecdhPub, convErr := pub.ECDH()
	if convErr != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedKey, convErr)
	}
	raw := ecdhPub.Bytes() // 0x04 || X(32) || Y(32) for P-256
	const want = 1 + 2*p256CoordLen
	if len(raw) != want {
		return nil, nil, fmt.Errorf("%w: unexpected P-256 point length %d", ErrUnsupportedKey, len(raw))
	}
	return raw[1 : 1+p256CoordLen], raw[1+p256CoordLen:], nil
}
