// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package soarverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// keyringEntry is the on-disk form of one SOAR principal: operator-authored
// JSON, hex-encoded Ed25519 public keys. DisallowUnknownFields at decode: a
// typo'd field name must refuse, not silently drop the constraint it set.
type keyringEntry struct {
	Name   string   `json:"name"`
	Tenant string   `json:"tenant"`
	Keys   []string `json:"keys"`
}

// LoadKeyring reads the SOAR keyring file (a JSON array of principals) and
// returns the decoded principals, ready for New. Every refusal names the
// offending principal: a keyring that half-loads would verify some principals
// and silently drop others, and the dropped one is discovered during the
// incident its key was provisioned for.
func LoadKeyring(path string) ([]Principal, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator's -soar-keyring flag
	if err != nil {
		return nil, fmt.Errorf("soarverify: read keyring %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var entries []keyringEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("soarverify: decode keyring %q: %w", path, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("soarverify: keyring %q is empty; no SOAR revoke could ever verify", path)
	}
	principals := make([]Principal, 0, len(entries))
	for _, e := range entries {
		p := Principal{Name: e.Name, Tenant: e.Tenant}
		for j, kh := range e.Keys {
			k, err := hex.DecodeString(kh)
			if err != nil {
				return nil, fmt.Errorf("soarverify: principal %q key %d: not hex: %w", e.Name, j, err)
			}
			if len(k) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("soarverify: principal %q key %d is %d bytes, want %d",
					e.Name, j, len(k), ed25519.PublicKeySize)
			}
			p.Keys = append(p.Keys, ed25519.PublicKey(k))
		}
		principals = append(principals, p)
	}
	return principals, nil
}
