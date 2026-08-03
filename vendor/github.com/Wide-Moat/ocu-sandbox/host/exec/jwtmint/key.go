// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package jwtmint holds the host-local Ed25519 signing key and mints the
// short-lived Session JWT presented to the guest on dial. The host is the sole
// minter; the guest is the sole verifier. The on-disk key is the raw 32-byte
// Ed25519 seed (0600); the 64-byte private key is derived in memory at mint
// time and never persisted. Neither key material nor minted tokens ever appear
// in a returned error or a log line.
package jwtmint

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrSeedSize is returned when an on-disk seed (or a seed handed to
// NewKeyFromSeed) is not exactly ed25519.SeedSize bytes. The error never
// embeds key bytes.
var ErrSeedSize = errors.New("jwtmint: seed must be exactly 32 bytes")

// ErrSeedPerms is returned when the seed file is readable by group or other.
// A host signing key must be 0600. The error never embeds key bytes.
var ErrSeedPerms = errors.New("jwtmint: seed file must be 0600 (no group/other access)")

// seedPerms is the only acceptable file mode for the on-disk seed.
const seedPerms fs.FileMode = 0o600

// LoadSeed reads the host signing seed from path at startup. It fails safe:
// the file must be exactly ed25519.SeedSize (32) bytes and must not be
// readable by group or other (0600). Any mismatch is a typed error and no
// seed is returned. The returned error never contains key bytes.
func LoadSeed(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("jwtmint: stat seed: %w", err)
	}
	// Reject any group/other permission bits. Only owner read/write allowed.
	if info.Mode().Perm()&^seedPerms != 0 {
		return nil, ErrSeedPerms
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jwtmint: read seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, ErrSeedSize
	}
	return seed, nil
}

// GenerateSeed writes a fresh crypto/rand 32-byte seed to path at 0600. It is
// the first-use generation path for the host signing key. The file is created
// with 0600; an existing file at path is overwritten.
func GenerateSeed(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("jwtmint: generate seed: %w", err)
	}
	if err := os.WriteFile(path, seed, seedPerms); err != nil {
		return fmt.Errorf("jwtmint: write seed: %w", err)
	}
	return nil
}

// NewKeyFromSeed derives the 64-byte Ed25519 private key from the raw 32-byte
// seed. The expanded key lives only in memory and is never persisted. A seed
// of any other length is a typed error (and never appears in the error text).
func NewKeyFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrSeedSize
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ExportPublicKey writes the raw 32-byte Ed25519 public key derived from priv
// to path. This is exactly the byte form the guest's --auth-public-key file
// consumes: the raw public key, not the 64-byte private key and not a DER
// wrapping. The file is written 0644 (the public key is not secret).
func ExportPublicKey(priv ed25519.PrivateKey, path string) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("jwtmint: private key did not yield an ed25519 public key")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("jwtmint: derived public key has wrong size %d", len(pub))
	}
	if err := os.WriteFile(path, pub, 0o644); err != nil {
		return fmt.Errorf("jwtmint: write public key: %w", err)
	}
	return nil
}
