// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
)

// ellipticP256 names the single supported EC curve, isolated so the key parser
// and the kid deriver agree on it.
func ellipticP256() elliptic.Curve { return elliptic.P256() }

// kidFor derives a stable key id from the public key: a base64url SHA-256
// thumbprint over the PKIX (SubjectPublicKeyInfo) DER encoding. Deriving the kid
// from the public material means the same key always carries the same kid across
// a restart, and the JWKS kid matches the minted-token kid without a side
// registry. PKIX encoding is non-deprecated and covers both supported key
// families; a key the parser already accepted always encodes cleanly.
func kidFor(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Only reachable for a key the loader would already have rejected; an
		// empty thumbprint yields a kid that matches nothing, which is the safe
		// fail-closed outcome rather than a panic.
		return ""
	}
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// toMap renders a typed claims struct into the generic map golang-jwt's
// MapClaims signs. It round-trips through JSON so the json tags on the claims
// structs are the single source of the wire field names, keeping the signed body
// field-identical to the typed StorageClaims/execClaims.
func toMap(claims any) map[string]any {
	b, err := json.Marshal(claims)
	if err != nil {
		// The claims structs marshal cleanly; a marshal error here would be a
		// programmer error, not a runtime input, so an empty map (which yields an
		// unusable, immediately-rejected token) is the safe fail-closed result.
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}
