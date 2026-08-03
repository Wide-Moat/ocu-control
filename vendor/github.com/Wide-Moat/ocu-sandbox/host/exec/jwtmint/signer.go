// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwtmint

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// maxTTL is the hard upper bound on a minted token's lifetime (AUTH-04). Any
// requested TTL above this is clamped down to it.
const maxTTL = 60 * time.Minute

// jwsHeader is the fixed compact-JWS header. EdDSA is pinned; the guest rejects
// any other algorithm.
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// jwsClaims is the minimal Session JWT claim set the guest verifies: sub binds
// the token to one container, exp bounds its lifetime, iat records issuance.
type jwsClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// Signer mints short-lived Session JWTs for one container over a host-local
// Ed25519 private key. The host is the sole minter; the guest is the sole
// verifier. A Signer holds the derived 64-byte private key in memory only.
type Signer struct {
	priv          ed25519.PrivateKey
	containerName string
}

// NewSigner builds a Signer over an already-derived private key (see
// NewKeyFromSeed) and the container name that becomes the token's sub claim.
func NewSigner(priv ed25519.PrivateKey, containerName string) *Signer {
	return &Signer{priv: priv, containerName: containerName}
}

// Mint builds a compact JWS Session JWT for this Signer's container. The token
// is base64url(header).base64url(claims).base64url(signature), where the
// signature is ed25519 over the signing input. All base64 is RawURLEncoding
// (unpadded base64url), so the first byte is always 'e' (from eyJ...), which is
// exactly the guest's prod-mode msg1 dispatch byte.
//
// ttl is clamped to maxTTL (60 minutes, AUTH-04); a ttl at or below the cap is
// honored exactly. The minted token is never logged nor embedded in an error.
func (s *Signer) Mint(ttl time.Duration) (string, error) {
	if ttl > maxTTL {
		ttl = maxTTL
	}
	now := time.Now()
	iat := now.Unix()
	exp := now.Add(ttl).Unix()

	header := jwsHeader{Alg: "EdDSA", Typ: "JWT"}
	claims := jwsClaims{Sub: s.containerName, Iat: iat, Exp: exp}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jwtmint: marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwtmint: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	sig := ed25519.Sign(s.priv, []byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, nil
}
