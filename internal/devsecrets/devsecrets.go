// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package devsecrets materializes the local development Storage-JWT signing key
// so the first-run quickstart and the compose default actually boot. The daemon
// is fail-closed on a missing -jwt-signing-key (there is no daemon-default key),
// and the compose file defaults the mount source to a path that does not exist
// in a fresh checkout; this package writes a real, loadable key at that path.
//
// It is a DEV convenience only: the generated key targets the default eddsa
// signing algorithm, and a production deployment provisions its signing key out
// of band. The output is a PKCS8-PEM Ed25519 private key — the exact on-disk
// form the cred mount loader accepts for the default alg — written 0600 so it is
// never world-readable, and the whole dev-secrets directory is gitignored so a
// dev key is never staged.
package devsecrets

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// keyMode is the on-disk permission of a generated signing key: owner-only read
// and write, never group- or world-readable.
const keyMode os.FileMode = 0o600

// dirMode is the permission of the parent directory the generator creates: owner
// traverse/read/write only.
const dirMode os.FileMode = 0o700

// GenerateDevSigningKey writes a fresh PKCS8-PEM Ed25519 private key at path,
// creating the parent directory if absent. It is the single code path the
// `make dev-secrets` target invokes (via the build-ignored cmd wrapper) and the
// path the test exercises, so the shipped key-gen and the tested key-gen are the
// same function.
//
// It is IDEMPOTENT and never overwrites: if path already holds a key, it returns
// created=false with a nil error and leaves the existing bytes untouched, so a
// re-run does not rotate a key a running deployment already mounted. Otherwise it
// generates a new key, writes it 0600, and returns created=true.
//
// The output is byte-shaped exactly like the cred mount loader expects for the
// default eddsa alg: a "PRIVATE KEY" PEM block wrapping the PKCS8 DER of an
// Ed25519 private key. Only stdlib crypto is used — zero external dependencies,
// matching the minimal-shelf rule.
func GenerateDevSigningKey(path string) (created bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		// A key is already present: leave it as-is. This is the idempotent
		// re-run path, not an error — a dev key once materialized is stable so a
		// running mount is never silently rotated out from under the daemon.
		return false, nil
	} else if !os.IsNotExist(statErr) {
		// Any stat error other than "not found" (e.g. a permission fault on the
		// directory) is fail-loud: we will not blindly overwrite under an
		// ambiguous filesystem state.
		return false, fmt.Errorf("devsecrets: stat %s: %w", path, statErr)
	}

	if mkErr := os.MkdirAll(filepath.Dir(path), dirMode); mkErr != nil {
		return false, fmt.Errorf("devsecrets: create dir for %s: %w", path, mkErr)
	}

	_, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return false, fmt.Errorf("devsecrets: generate ed25519 key: %w", genErr)
	}
	der, marshalErr := x509.MarshalPKCS8PrivateKey(priv)
	if marshalErr != nil {
		return false, fmt.Errorf("devsecrets: marshal pkcs8: %w", marshalErr)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if writeErr := os.WriteFile(path, pemBytes, keyMode); writeErr != nil {
		return false, fmt.Errorf("devsecrets: write key %s: %w", path, writeErr)
	}
	return true, nil
}
