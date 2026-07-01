// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package devsecrets_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/devsecrets"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// genClockStart is the fixed instant the loader runs on, so the test is
// reproducible and a minted token's iat/exp are deterministic.
var genClockStart = time.Date(2026, time.June, 20, 12, 0, 0, 0, time.UTC)

// loadGenerated loads a signer over path through the REAL cred mount loader on
// the default eddsa alg with a short fixed Storage-JWT window — the exact path
// the daemon boots through. It returns the loader error verbatim so the
// malformed-key guard can assert ErrSigningKeyInvalid.
func loadGenerated(t *testing.T, path string) (*cred.Signer, error) {
	t.Helper()
	clk := state.NewFakeClock(genClockStart)
	cfg := cred.Config{
		Alg:             cred.AlgEdDSA,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		StorageTTL:      time.Minute,
	}
	return cred.LoadSignerFromMount(path, clk, cfg)
}

// TestGenerateDevSigningKey is the load-bearing proof that the key the generator
// writes is not merely a file that exists but a real, loadable, mint-and-verify
// Ed25519 PKCS8 key for the default alg — and that the generator is idempotent,
// 0600, and creates its parent directory.
func TestGenerateDevSigningKey(t *testing.T) {
	// T1 — generated key is loadable, and a real working signer end-to-end.
	t.Run("generated_key_is_loadable_and_mints", func(t *testing.T) {
		// Generate into a non-existent sub path so the parent-dir branch runs.
		path := filepath.Join(t.TempDir(), "sub", "storage-jwt-signing.key")
		created, err := devsecrets.GenerateDevSigningKey(path)
		if err != nil {
			t.Fatalf("GenerateDevSigningKey: %v", err)
		}
		if !created {
			t.Fatalf("created = false on a fresh path, want true")
		}

		// Load the produced file through the REAL loader.
		signer, err := loadGenerated(t, path)
		if err != nil {
			t.Fatalf("LoadSignerFromMount over the generated key: %v", err)
		}
		if signer.ActiveKID() == "" {
			t.Fatalf("loaded signer has an empty ActiveKID, want a derived kid")
		}

		// Prove it is a working signer: mint a Storage-JWT.
		tok, err := signer.MintStorageJWT(context.Background(), cred.StorageMintReq{
			FilesystemID: "fs-dev",
			Authz:        cred.AuthorizationMetadata{Intent: cred.IntentRead},
		})
		if err != nil {
			t.Fatalf("MintStorageJWT over the generated key: %v", err)
		}
		if tok.IsZero() {
			t.Fatalf("minted token is the zero Token, want a signed JWT")
		}

		// Verify the minted token against the signer's published public key:
		// the signature must verify under the Ed25519 public half and the JWS
		// alg header must be EdDSA — proving the generated key is the default
		// alg's family, signed and verifiable end to end.
		pubs := signer.PublicKeys()
		if len(pubs) != 1 {
			t.Fatalf("PublicKeys() len = %d, want exactly the active key", len(pubs))
		}
		edPub, ok := pubs[0].Pub.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("published key is %T, want ed25519.PublicKey for the default alg", pubs[0].Pub)
		}
		// Validate the SIGNATURE and the alg header, not the claim freshness: the
		// token is minted on a FakeClock anchored to a fixed instant with a short
		// fixed window, so its exp is in the past relative to the wall clock the
		// parser would otherwise check. The load-bearing assertion is that the
		// generated key's public half verifies the signature under EdDSA.
		parsed, err := jwt.Parse(tok.Reveal(), func(tk *jwt.Token) (any, error) {
			if tk.Method.Alg() != "EdDSA" {
				t.Fatalf("minted JWS alg = %q, want EdDSA", tk.Method.Alg())
			}
			return edPub, nil
		}, jwt.WithoutClaimsValidation())
		if err != nil {
			t.Fatalf("verify minted token under the published Ed25519 key: %v", err)
		}
		if !parsed.Valid {
			t.Fatalf("minted token did not verify under the generated key's public half")
		}
	})

	// T2 — file mode 0600 and the parent directory was created.
	t.Run("file_mode_0600_and_parent_created", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nested")
		path := filepath.Join(dir, "storage-jwt-signing.key")
		if _, err := devsecrets.GenerateDevSigningKey(path); err != nil {
			t.Fatalf("GenerateDevSigningKey: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat generated key: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("key mode = %v, want 0600 (owner-only)", got)
		}
		if dInfo, err := os.Stat(dir); err != nil {
			t.Fatalf("parent dir was not created: %v", err)
		} else if !dInfo.IsDir() {
			t.Fatalf("parent path %s is not a directory", dir)
		}
	})

	// T3 — idempotent: a second call does not overwrite the existing key.
	t.Run("idempotent_no_overwrite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "storage-jwt-signing.key")
		created, err := devsecrets.GenerateDevSigningKey(path)
		if err != nil || !created {
			t.Fatalf("first GenerateDevSigningKey: created=%v err=%v", created, err)
		}
		first, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read first key: %v", err)
		}

		created2, err := devsecrets.GenerateDevSigningKey(path)
		if err != nil {
			t.Fatalf("second GenerateDevSigningKey: %v", err)
		}
		if created2 {
			t.Fatalf("second call created = true, want false (must not overwrite)")
		}
		second, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read second key: %v", err)
		}
		if string(first) != string(second) {
			t.Fatalf("key bytes changed on the idempotent re-run: the existing key was overwritten")
		}
	})

	// T4 — loader-exercise non-vacuity anchor: a deliberately malformed key must
	// fail the REAL loader with ErrSigningKeyInvalid. This proves T1's success is
	// not vacuous — a bad key genuinely fails the same loader a good key passes.
	t.Run("malformed_key_fails_load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "storage-jwt-signing.key")
		if err := os.WriteFile(path, []byte("not a pkcs8 key"), 0o600); err != nil {
			t.Fatalf("write malformed key: %v", err)
		}
		_, err := loadGenerated(t, path)
		if !errors.Is(err, cred.ErrSigningKeyInvalid) {
			t.Fatalf("LoadSignerFromMount over a malformed key = %v, want ErrSigningKeyInvalid", err)
		}
	})
}
