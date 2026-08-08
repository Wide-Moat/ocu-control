// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package operator_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/ingress/operator"
	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/soarverify"
)

// The D3 wiring keystone: the CONCRETE ADR-0039 verifier — built from a
// keyring FILE exactly as the daemon builds it — drives the verify-then-mint
// fence end to end. The fence suites bind against a fake verifier; this one
// closes the loaded-keyring -> Ed25519 trial-verify -> minted-principal link
// the daemon flag actually wires.
func TestSOARFenceWithLoadedKeyringVerifier(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal([]map[string]any{{
		"name": "soar-prod", "tenant": "acme",
		"keys": []string{hex.EncodeToString(pub)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(t.TempDir(), "soar-keyring.json")
	if err := os.WriteFile(keyringPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// The daemon's exact construction: LoadKeyring -> New.
	principals, err := soarverify.LoadKeyring(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := soarverify.New(principals)
	if err != nil {
		t.Fatal(err)
	}

	h, sink, store := newTestHandlers(t, operator.NewPeerCredResolver(nil), verifier)

	payload := []byte(`{"reason":"incident-4711"}`)
	sig := ed25519.Sign(priv, payload)

	// A forged signature refuses through the REAL verifier, nothing authored.
	forged := make([]byte, len(sig))
	copy(forged, sig)
	forged[0] ^= 0x01
	if err := h.RevokeAllViaSOAR(context.Background(), attestedConn(1001), payload, forged, "soar"); !errors.Is(err, killswitch.ErrSOARUnverified) {
		t.Fatalf("forged signature through the real verifier = %v, want ErrSOARUnverified", err)
	}
	if deny, _ := store.LoadDeny(context.Background()); len(deny) != 0 {
		t.Fatalf("a forged SOAR revoke authored %d deny entries", len(deny))
	}

	// The genuine signature mints and revokes, and the audit actor is the
	// KEYRING principal — config-derived, never the socket peer or the body.
	if err := h.RevokeAllViaSOAR(context.Background(), attestedConn(1001), payload, sig, "soar"); err != nil {
		t.Fatalf("genuine SOAR revoke through the loaded keyring: %v", err)
	}
	if deny, _ := store.LoadDeny(context.Background()); len(deny) == 0 {
		t.Fatal("a verified SOAR RevokeAll authored no deny entries")
	}
	found := false
	for _, rec := range sink.Records() {
		if rec.Caller == "soar-prod" && rec.Tenant == "acme" {
			found = true
		}
	}
	if !found {
		t.Fatal("no audit record names the keyring principal {acme, soar-prod} as the " +
			"actor; the minted scope did not carry the verified signer (P2-R2)")
	}
}
