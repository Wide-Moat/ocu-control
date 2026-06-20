// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/jwks"
)

// TestPublishRefusesUnrenderableKeys covers toJWK's fail-closed branches reached
// through Publish: an unknown alg, an EdDSA tag over a non-ed25519 key, and an ES256
// tag over a non-ecdsa key are each ErrUnsupportedKey — a key the publisher cannot
// render is never silently omitted (a live token could have been minted under it).
func TestPublishRefusesUnrenderableKeys(t *testing.T) {
	t.Parallel()
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}

	cases := []struct {
		name string
		key  cred.PublicKey
	}{
		{"unknown alg", cred.PublicKey{KID: "k1", Alg: cred.Alg(99), Pub: edPub}},
		{"eddsa tag over ecdsa key", cred.PublicKey{KID: "k2", Alg: cred.AlgEdDSA, Pub: &ecKey.PublicKey}},
		{"es256 tag over ed25519 key", cred.PublicKey{KID: "k3", Alg: cred.AlgES256, Pub: edPub}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwks.Publish([]cred.PublicKey{tc.key})
			if !errors.Is(err, jwks.ErrUnsupportedKey) {
				t.Fatalf("Publish(%s) = %v, want ErrUnsupportedKey", tc.name, err)
			}
		})
	}
}

// TestPublishEd25519CarriesNoYCoord proves the OKP branch of toJWK renders the x
// coordinate and leaves y absent, the shape the OKP JWK requires (a stray y would
// mark it as an EC key to a consumer).
func TestPublishEd25519CarriesNoYCoord(t *testing.T) {
	t.Parallel()
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	set, err := jwks.Publish([]cred.PublicKey{{KID: "k1", Alg: cred.AlgEdDSA, Pub: edPub}})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("published %d keys, want 1", len(set.Keys))
	}
	if set.Keys[0].X == "" {
		t.Fatal("OKP JWK has empty x; the public key was not rendered")
	}
	if set.Keys[0].Y != "" {
		t.Fatalf("OKP JWK carries a y coordinate %q; want absent", set.Keys[0].Y)
	}
}
