// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package guestexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

// newTestSigner builds a REAL cred.Signer over a fresh Ed25519 key staged the way
// the daemon loads it, so the minter tests exercise the production mint path and
// the emitted JWT verifies against the same key.
func newTestSigner(t *testing.T) (*cred.Signer, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key mount: %v", err)
	}
	signer, err := cred.LoadSignerFromMount(path, state.SystemClock(), cred.Config{
		Alg:             cred.AlgEdDSA,
		StorageIssuer:   "https://control.example/provisional",
		StorageAudience: "egress.provisional",
		ExecIssuer:      "https://control.example/exec-provisional",
		ExecAudience:    "guest.exec.provisional",
		StorageTTL:      15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("LoadSignerFromMount: %v", err)
	}
	signer.UseRevoker(cred.NewRevoker(state.SystemClock()))
	return signer, pub
}

// TestMinterMintsContainerBoundJWT pins the adapter contract: Mint(ttl) mints a
// REAL exec JWT through the production Signer with sub bound to the adapter's
// container name, and the compact token verifies against the signing key.
func TestMinterMintsContainerBoundJWT(t *testing.T) {
	t.Parallel()
	signer, pub := newTestSigner(t)
	m, err := NewMinter(signer, "ocu-session-ctr-1")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	raw, err := m.Mint(30 * time.Second)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		t.Fatalf("parse minted exec JWT: %v", err)
	}
	if sub, _ := claims["sub"].(string); sub != "ocu-session-ctr-1" {
		t.Fatalf("exec JWT sub = %q; want the bound container name", sub)
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatal("exec JWT missing exp claim")
	}
}

// TestNewMinterRefusesEmptyContainerName pins the identity precondition: an
// adapter with no container binding must never exist, so a dial cannot mint an
// unbound Session JWT.
func TestNewMinterRefusesEmptyContainerName(t *testing.T) {
	t.Parallel()
	signer, _ := newTestSigner(t)
	if _, err := NewMinter(signer, ""); err == nil {
		t.Fatal("NewMinter with empty container name = nil error; want refusal")
	}
}

// failingMinter is a narrow execMinter fake whose mint always fails, so the
// adapter's error propagation is observable without key custody.
type failingMinter struct{ err error }

func (f failingMinter) MintExecJWT(context.Context, cred.ExecMintReq) (cred.Token, error) {
	return cred.Token{}, f.err
}

// TestMinterPropagatesMintError pins that a mint failure surfaces to the dial
// (which refuses the handshake) rather than yielding an empty token.
func TestMinterPropagatesMintError(t *testing.T) {
	t.Parallel()
	boom := errors.New("mint refused")
	m, err := NewMinter(failingMinter{err: boom}, "ctr")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	if _, err := m.Mint(time.Second); !errors.Is(err, boom) {
		t.Fatalf("Mint error = %v; want the propagated mint refusal", err)
	}
}

// stagedSockDir builds the real handoff layout — a 0700 per-session ROOT with a
// 0777 sock LEAF inside it (the exact shape handoff.Stager writes: the leaf is
// world-writable by design so the CapDrop-ALL guest can bind(2) its socket, while
// the 0700 root parent is the trust wall). It returns the leaf, which is what the
// driver passes to the gate.
func stagedSockDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	leaf := filepath.Join(root, "sock")
	if err := os.Mkdir(leaf, 0o777); err != nil {
		t.Fatalf("mkdir leaf: %v", err)
	}
	if err := os.Chmod(leaf, 0o777); err != nil {
		t.Fatalf("chmod leaf: %v", err)
	}
	return leaf
}

// TestVerifyHostOwnedDir pins the pre-connect gate on the REAL staged layout: the
// sock LEAF is a 0777 euid-owned directory (so the CapDrop guest can bind(2)), and
// the gate's trust check is on the ROOT PARENT — it must be an exactly-0700
// host-owned directory. A world/group-accessible PARENT, a missing path, or a
// plain file is refused with ErrSockDirGate BEFORE any connect(2). The leaf's own
// 0777 mode is NOT a rejection reason (that was the bug that killed every exec).
func TestVerifyHostOwnedDir(t *testing.T) {
	t.Parallel()

	t.Run("0777 leaf under a 0700 root passes", func(t *testing.T) {
		t.Parallel()
		leaf := stagedSockDir(t)
		if err := verifyHostOwnedDir(leaf); err != nil {
			t.Fatalf("verifyHostOwnedDir(0777 leaf / 0700 root) = %v; want nil", err)
		}
	})

	t.Run("group-accessible PARENT refused", func(t *testing.T) {
		t.Parallel()
		leaf := stagedSockDir(t)
		if err := os.Chmod(filepath.Dir(leaf), 0o750); err != nil {
			t.Fatalf("chmod parent: %v", err)
		}
		if err := verifyHostOwnedDir(leaf); !errors.Is(err, ErrSockDirGate) {
			t.Fatalf("verifyHostOwnedDir(0750 parent) = %v; want ErrSockDirGate", err)
		}
	})

	t.Run("missing path refused", func(t *testing.T) {
		t.Parallel()
		if err := verifyHostOwnedDir(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, ErrSockDirGate) {
			t.Fatalf("verifyHostOwnedDir(absent) = %v; want ErrSockDirGate", err)
		}
	})

	t.Run("plain file leaf refused", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		path := filepath.Join(root, "sock")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := verifyHostOwnedDir(path); !errors.Is(err, ErrSockDirGate) {
			t.Fatalf("verifyHostOwnedDir(file leaf) = %v; want ErrSockDirGate", err)
		}
	})

	t.Run("empty path refused", func(t *testing.T) {
		t.Parallel()
		if err := verifyHostOwnedDir(""); !errors.Is(err, ErrSockDirGate) {
			t.Fatalf("verifyHostOwnedDir(\"\") = %v; want ErrSockDirGate", err)
		}
	})
}
