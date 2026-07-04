// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package cred_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// testStart is the fixed instant every cred test anchors its FakeClock on, so
// runs are reproducible and a setback is expressed relative to it.
var testStart = time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)

// newTestExecSigner builds an ExecSigner over a fresh exec Ed25519 key and returns
// it with the matching public half (the value the handoff would stage as the
// guest verify key), so a test can mint and verify an exec JWT.
func newTestExecSigner(t *testing.T) (*cred.ExecSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate exec key: %v", err)
	}
	return cred.NewExecSigner(priv), pub
}

// keyMountTB is the testing.TB subset writeKeyMount needs, so both *testing.T
// and *rapid.T (via rapidTB) can drive it.
type keyMountTB interface {
	Helper()
	Fatalf(format string, args ...any)
	TempDir() string
}

// writeKeyMount writes a PKCS8 PEM private key for alg into a temp file and
// returns the path, modelling the -jwt-signing-key config/secret mount.
func writeKeyMount(t keyMountTB, alg cred.Alg) string {
	t.Helper()
	var key any
	switch alg {
	case cred.AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate ed25519: %v", err)
		}
		key = priv
	case cred.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa: %v", err)
		}
		key = priv
	default:
		t.Fatalf("unsupported alg %v", alg)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
	return path
}

// newTestSigner loads a Signer over a freshly generated key for alg on a
// FakeClock anchored at testStart with the given storage TTL.
func newTestSigner(t *testing.T, alg cred.Alg, storageTTL time.Duration) (*cred.Signer, *state.FakeClock) {
	t.Helper()
	clk := state.NewFakeClock(testStart)
	cfg := cred.Config{
		Alg:             alg,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		ExecIssuer:      "https://control.example/exec-provisional",
		ExecAudience:    "guest.exec.provisional",
		StorageTTL:      storageTTL,
	}
	signer, err := cred.LoadSignerFromMount(writeKeyMount(t, alg), clk, cfg)
	if err != nil {
		t.Fatalf("LoadSignerFromMount: %v", err)
	}
	return signer, clk
}

// freshEd25519Key returns a new Ed25519 signer for the rotation test.
func freshEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return priv
}
