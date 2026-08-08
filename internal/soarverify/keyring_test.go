// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package soarverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The keyring file is the operator-authored SOAR trust root (ADR-0039): JSON
// principals with hex Ed25519 keys. Loading refuses malformed entries with a
// diagnostic naming the entry — a keyring that half-loads would verify some
// principals and silently drop others, and the dropped one is discovered
// during the incident its key was provisioned for.

func writeKeyring(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "soar-keyring.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKeyringRoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writeKeyring(t, []map[string]any{{
		"name": "soar-prod", "tenant": "acme",
		"keys": []string{hex.EncodeToString(pub)},
	}})
	principals, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(principals) != 1 || principals[0].Name != "soar-prod" ||
		principals[0].Tenant != "acme" || len(principals[0].Keys) != 1 {
		t.Fatalf("loaded %+v", principals)
	}
	// The loaded keyring builds a working verifier end to end.
	if _, err := New(principals); err != nil {
		t.Fatalf("New over loaded keyring: %v", err)
	}
}

func TestLoadKeyringRefusesBadHex(t *testing.T) {
	path := writeKeyring(t, []map[string]any{{
		"name": "soar-prod", "tenant": "acme", "keys": []string{"zz-not-hex"},
	}})
	_, err := LoadKeyring(path)
	if err == nil || !strings.Contains(err.Error(), "soar-prod") {
		t.Fatalf("bad-hex load error = %v, want a refusal naming the principal", err)
	}
}

func TestLoadKeyringRefusesWrongSizeKey(t *testing.T) {
	path := writeKeyring(t, []map[string]any{{
		"name": "soar-prod", "tenant": "acme",
		"keys": []string{hex.EncodeToString([]byte("short"))},
	}})
	_, err := LoadKeyring(path)
	if err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("wrong-size load error = %v, want a refusal naming the expected size", err)
	}
}

func TestLoadKeyringRefusesEmptyFile(t *testing.T) {
	path := writeKeyring(t, []map[string]any{})
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("an empty keyring loaded; no SOAR revoke could ever verify and the " +
			"operator learns during the incident")
	}
}

func TestLoadKeyringRefusesUnknownFields(t *testing.T) {
	path := writeKeyring(t, []map[string]any{{
		"name": "soar-prod", "tenant": "acme",
		"keys": []string{hex.EncodeToString(make([]byte, 32))},
		"kid":  "typo-field",
	}})
	if _, err := LoadKeyring(path); err == nil {
		t.Fatal("a keyring with an unknown field loaded; a typo'd field name would " +
			"silently drop the constraint it was meant to set")
	}
}
