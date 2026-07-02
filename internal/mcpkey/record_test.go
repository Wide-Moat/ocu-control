// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// fixedClock is a deterministic Clock for record tests.
type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time                     { return f.t }
func (f fixedClock) Since(mark time.Time) time.Duration { return f.t.Sub(mark) }

var epoch = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

// TestNewRecordSaltedHash is the salted-hash property test:
// key_hash == sha256(salt ‖ secret), recomputed independently.
func TestNewRecordSaltedHash(t *testing.T) {
	t.Parallel()
	m := mcpkey.DefaultMinter()
	clk := fixedClock{epoch}

	for i := range 200 {
		sk, err := m.Mint()
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
		rec, err := mcpkey.NewRecord(sk, "tenant-a", "deploy-1", time.Time{}, clk)
		if err != nil {
			t.Fatalf("NewRecord #%d: %v", i, err)
		}

		// Recompute sha256(salt ‖ secret) independently.
		raw := sk.Reveal()
		h := sha256.New()
		h.Write(rec.Salt)
		h.Write([]byte(raw))
		want := h.Sum(nil)

		if !bytes.Equal(rec.KeyHash, want) {
			t.Fatalf("record #%d: key_hash mismatch\n  got:  %x\n  want: %x", i, rec.KeyHash, want)
		}
	}
}

// TestNewRecordUnsaltedRejected proves that a salt of all-zeros or empty is
// rejected at construction with ErrUnsalted (pass-the-hash floor, NFR-SEC-87).
func TestNewRecordUnsaltedRejected(t *testing.T) {
	t.Parallel()
	// We use the internal constructor that accepts an explicit salt so we can
	// inject a bad salt and confirm ErrUnsalted is returned.
	// This test drives NewRecordWithSalt (exported for test via export_test.go).
	sk := mcpkey.NewSecretKeyForTest("sk-ocu-somefakekey0000000000000000000000000")
	clk := fixedClock{epoch}

	// Zero-length salt.
	_, err := mcpkey.NewRecordWithSalt(sk, []byte{}, "t", "d", time.Time{}, clk)
	if !errors.Is(err, mcpkey.ErrUnsalted) {
		t.Fatalf("empty salt: want ErrUnsalted, got %v", err)
	}

	// All-zero 32-byte salt.
	zeroSalt := make([]byte, 32)
	_, err = mcpkey.NewRecordWithSalt(sk, zeroSalt, "t", "d", time.Time{}, clk)
	if !errors.Is(err, mcpkey.ErrUnsalted) {
		t.Fatalf("all-zero 32-byte salt: want ErrUnsalted, got %v", err)
	}
}

// TestNewRecordSaltUniqueness proves that N records over real crypto/rand carry N
// distinct 32-byte salts (per-key salt uniqueness, NFR-SEC-87, T-08-07).
func TestNewRecordSaltUniqueness(t *testing.T) {
	t.Parallel()
	const N = 500
	m := mcpkey.DefaultMinter()
	clk := fixedClock{epoch}
	seen := make(map[string]struct{}, N)

	for i := range N {
		sk, err := m.Mint()
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
		rec, err := mcpkey.NewRecord(sk, "t", "d", time.Time{}, clk)
		if err != nil {
			t.Fatalf("NewRecord #%d: %v", i, err)
		}
		if len(rec.Salt) != 32 {
			t.Fatalf("record #%d: salt len %d; want 32", i, len(rec.Salt))
		}
		key := string(rec.Salt)
		if _, dup := seen[key]; dup {
			t.Fatalf("record #%d: duplicate salt found", i)
		}
		seen[key] = struct{}{}
	}
	if len(seen) != N {
		t.Fatalf("salt uniqueness: got %d distinct salts; want %d", len(seen), N)
	}
}

// TestNewRecordFields proves the per-caller fields are wired correctly:
// tenant, deployment, status, created_at, expires_at.
func TestNewRecordFields(t *testing.T) {
	t.Parallel()
	m := mcpkey.DefaultMinter()
	sk, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	now := epoch
	expiry := now.Add(24 * time.Hour)
	clk := fixedClock{now}

	rec, err := mcpkey.NewRecord(sk, "tenant-x", "deploy-y", expiry, clk)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}

	if rec.Tenant != "tenant-x" {
		t.Errorf("Tenant: got %q; want %q", rec.Tenant, "tenant-x")
	}
	if rec.Deployment != "deploy-y" {
		t.Errorf("Deployment: got %q; want %q", rec.Deployment, "deploy-y")
	}
	if rec.Status != mcpkey.StatusActive {
		t.Errorf("Status: got %q; want %q", rec.Status, mcpkey.StatusActive)
	}
	if !rec.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt: got %v; want %v", rec.CreatedAt, now)
	}
	if !rec.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt: got %v; want %v", rec.ExpiresAt, expiry)
	}

	// Non-expiring: zero expiry means IsExpired always returns false.
	nonExp, err := mcpkey.NewRecord(sk, "t", "d", time.Time{}, clk)
	if err != nil {
		t.Fatalf("NewRecord non-expiring: %v", err)
	}
	if nonExp.ExpiresAt != (time.Time{}) {
		t.Errorf("non-expiring: ExpiresAt must be zero, got %v", nonExp.ExpiresAt)
	}
	if nonExp.IsExpired(time.Now().Add(100 * 365 * 24 * time.Hour)) {
		t.Error("non-expiring record must never report IsExpired=true")
	}
}

// TestNewRecordKeyIDDistinct proves that key_id is a short random handle
// distinct from the secret: two different keys get distinct IDs, and key_id
// is never a substring of Reveal.
func TestNewRecordKeyIDDistinct(t *testing.T) {
	t.Parallel()
	const N = 200
	m := mcpkey.DefaultMinter()
	clk := fixedClock{epoch}
	ids := make(map[string]struct{}, N)

	for i := range N {
		sk, err := m.Mint()
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
		rec, err := mcpkey.NewRecord(sk, "t", "d", time.Time{}, clk)
		if err != nil {
			t.Fatalf("NewRecord #%d: %v", i, err)
		}
		if rec.KeyID == "" {
			t.Fatalf("record #%d: KeyID must not be empty", i)
		}
		// key_id must not be a substring of the revealed secret.
		raw := sk.Reveal()
		if len(rec.KeyID) > 0 && containsSubstring(raw, rec.KeyID) {
			t.Fatalf("record #%d: KeyID %q is a substring of the secret — derived from it (forbidden)", i, rec.KeyID)
		}
		if _, dup := ids[rec.KeyID]; dup {
			t.Fatalf("record #%d: duplicate key_id %q", i, rec.KeyID)
		}
		ids[rec.KeyID] = struct{}{}
	}
}

// TestNewRecordKeyIDShape pins the DOCUMENTED key_id shape: the lowercase-hex
// encoding of 12 CSPRNG bytes = exactly 24 lowercase-hex characters. The
// existing distinctness test only asserted non-empty/distinct/not-a-substring, so
// an entropy-reducing regression (e.g. shrinking keyIDLen, which halves the random
// bytes) shipped green — a shorter handle is still non-empty and distinct. This
// guards the width and the alphabet so such a regression turns red.
func TestNewRecordKeyIDShape(t *testing.T) {
	t.Parallel()
	const wantHexLen = 24 // hex(12 bytes)
	m := mcpkey.DefaultMinter()
	clk := fixedClock{epoch}
	for i := range 200 {
		sk, err := m.Mint()
		if err != nil {
			t.Fatalf("Mint #%d: %v", i, err)
		}
		rec, err := mcpkey.NewRecord(sk, "t", "d", time.Time{}, clk)
		if err != nil {
			t.Fatalf("NewRecord #%d: %v", i, err)
		}
		if len(rec.KeyID) != wantHexLen {
			t.Fatalf("record #%d: key_id %q is %d chars, want exactly %d (hex of 12 CSPRNG bytes)", i, rec.KeyID, len(rec.KeyID), wantHexLen)
		}
		for j, c := range rec.KeyID {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("record #%d: key_id %q has a non-lowercase-hex char %q at %d", i, rec.KeyID, c, j)
			}
		}
	}
}

// TestNewRecordNoPlaintextField proves the Record struct has no field that holds
// the raw secret. A reflective walk over all fields confirms only KeyHash+Salt
// are byte slices, and none carries the raw sk-ocu- string.
func TestNewRecordNoPlaintextField(t *testing.T) {
	t.Parallel()
	m := mcpkey.DefaultMinter()
	sk, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	raw := sk.Reveal()
	clk := fixedClock{epoch}

	rec, err := mcpkey.NewRecord(sk, "t", "d", time.Time{}, clk)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}

	// Walk all exported fields of Record and check no string field holds the
	// raw secret.
	v := reflect.ValueOf(rec)
	rt := v.Type()
	for i := range rt.NumField() {
		f := v.Field(i)
		if f.Kind() == reflect.String {
			if f.String() == raw {
				t.Errorf("field %q holds the plaintext secret — forbidden", rt.Field(i).Name)
			}
		}
		if f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.Uint8 {
			// byte slice: must not equal raw as bytes
			if string(f.Bytes()) == raw {
				t.Errorf("byte field %q holds the plaintext secret — forbidden", rt.Field(i).Name)
			}
		}
	}
}

// TestRevokedHelper proves that Revoked() returns a new Record with
// status=revoked without mutating the original.
func TestRevokedHelper(t *testing.T) {
	t.Parallel()
	m := mcpkey.DefaultMinter()
	sk, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	clk := fixedClock{epoch}
	rec, err := mcpkey.NewRecord(sk, "t", "d", time.Time{}, clk)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}

	revoked := rec.Revoked()
	if revoked.Status != mcpkey.StatusRevoked {
		t.Errorf("Revoked().Status: got %q; want %q", revoked.Status, mcpkey.StatusRevoked)
	}
	// Original is unchanged.
	if rec.Status != mcpkey.StatusActive {
		t.Errorf("original record was mutated: Status now %q", rec.Status)
	}
	// Other fields are preserved.
	if revoked.KeyID != rec.KeyID {
		t.Errorf("Revoked().KeyID changed: %q → %q", rec.KeyID, revoked.KeyID)
	}
}

// TestIsActiveExpired exercises IsExpired and IsActive with time boundaries.
func TestIsActiveExpired(t *testing.T) {
	t.Parallel()
	m := mcpkey.DefaultMinter()
	sk, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	now := epoch
	clk := fixedClock{now}
	expiry := now.Add(time.Hour)

	rec, err := mcpkey.NewRecord(sk, "t", "d", expiry, clk)
	if err != nil {
		t.Fatalf("NewRecord: %v", err)
	}

	before := now.Add(-time.Second)
	after := now.Add(2 * time.Hour)

	if rec.IsExpired(before) {
		t.Error("record should not be expired before its expiry")
	}
	if !rec.IsExpired(after) {
		t.Error("record should be expired after its expiry")
	}
	if !rec.IsActive(before) {
		t.Error("active record before expiry should IsActive=true")
	}
	if rec.IsActive(after) {
		t.Error("active record after expiry should IsActive=false")
	}

	revoked := rec.Revoked()
	if revoked.IsActive(before) {
		t.Error("revoked record should never IsActive=true")
	}
}

// containsSubstring returns true if s contains sub as a substring.
func containsSubstring(s, sub string) bool {
	if len(sub) == 0 {
		return false
	}
	for i := range len(s) - len(sub) + 1 {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
