// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

const (
	skPrefix    = "sk-ocu-"
	base62Width = 43 // ceil(256 / log2(62)) = 43 chars
)

// TestMintShape verifies that every Mint result begins with "sk-ocu-" and the
// base62 body is exactly base62Width chars, regardless of how many mints are
// performed.
func TestMintShape(t *testing.T) {
	t.Parallel()
	m := mcpkey.DefaultMinter()
	for range 200 {
		sk, err := m.Mint()
		if err != nil {
			t.Fatalf("Mint() error: %v", err)
		}
		raw := sk.Reveal()
		if !strings.HasPrefix(raw, skPrefix) {
			t.Fatalf("key missing sk-ocu- prefix: %q", raw)
		}
		body := raw[len(skPrefix):]
		if len(body) != base62Width {
			t.Fatalf("base62 body width %d; want %d: %q", len(body), base62Width, raw)
		}
		// All chars must be in the base62 alphabet.
		for _, c := range body {
			if !isBase62(byte(c)) {
				t.Fatalf("non-base62 char %q in key body: %q", c, raw)
			}
		}
	}
}

// TestMintBiasFree proves that the sampler uses rejection sampling over the
// boundary byte 247 (the reject threshold is 256-256%62 = 248, so bytes >=248
// are discarded).
// It drives a white-box fake reader that feeds specific byte values and asserts
// that the accepted output uses only the range [0,62).
func TestMintBiasFree(t *testing.T) {
	t.Parallel()

	// Boundary bytes to test: 0, 61, 247 (just below threshold = accept),
	// 248 (= reject threshold, must be discarded), 255 (must be discarded).
	// Feed: [248, 255, 0] — first two rejected, 0 accepted.
	// The fake reader yields bytes in sequence, cycling as needed.
	fake := mcpkey.NewFakeReader([]byte{
		// Two bytes that must be rejected (>=248), followed by enough
		// accepted bytes (0..247) to fill 43 characters. We fill with 0,
		// which maps to alphabet[0] = '0'.
		248, 255,
		// 43 accepted bytes (0 maps to '0' in base62)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0,
	})

	m := mcpkey.NewMinterWithReader(fake)
	sk, err := m.Mint()
	if err != nil {
		t.Fatalf("Mint() with fake reader: %v", err)
	}
	raw := sk.Reveal()
	body := raw[len(skPrefix):]
	if len(body) != base62Width {
		t.Fatalf("body width %d; want %d", len(body), base62Width)
	}
	// All chars must be '0' (alphabet[0]) — rejected bytes were discarded.
	for i, c := range body {
		if c != '0' {
			t.Fatalf("position %d: got %q; expected all '0' chars (rejected bytes discarded)", i, c)
		}
	}
}

// biasForbiddenPatterns are the source fragments that would reintroduce sampling
// bias or a weak entropy source into the mint path, lowering entropy below the
// NFR-SEC-87 256-bit floor. TestMintNoBiasGrepGuard fails if any appears in a
// production (non-test) file of this package.
var biasForbiddenPatterns = []string{
	`"math/rand"`,  // the biased/non-crypto RNG; the mint path must use crypto/rand
	`math/rand/v2`, // the v2 import path of the same non-crypto RNG
	"% 62",         // naive modulo folding of a byte into base62 — the classic bias
	"%62",          // the same, unspaced
}

// TestMintNoBiasGrepGuard is a REAL static guard: it scans every production
// (non-test) .go file in this package and fails if any names a forbidden
// bias/weak-entropy fragment (math/rand, or a byte%62 modulo fold). It is not a
// documentation anchor — planting `"math/rand"` or a `b % 62` fold in the mint
// path turns this red. The behavioural companion is TestMintBiasFree; this guard
// catches the regression at the source level, before it can bias a single mint.
func TestMintNoBiasGrepGuard(t *testing.T) {
	t.Parallel()

	// Locate this package's directory from the test file, so the scan is
	// independent of the working directory go test runs in.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the package directory")
	}
	pkgDir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir %s: %v", pkgDir, err)
	}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for _, pat := range biasForbiddenPatterns {
			if strings.Contains(string(src), pat) {
				t.Errorf("production file %s contains forbidden bias/weak-entropy fragment %q; "+
					"the mint path must use crypto/rand with rejection sampling (NFR-SEC-87)", name, pat)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned 0 production files; the grep guard is pointed at the wrong directory")
	}
}

// TestMintFailClosed confirms that Mint returns an error and no SecretKey when
// the entropy source returns an error on any read.
func TestMintFailClosed(t *testing.T) {
	t.Parallel()
	errRand := errors.New("entropy source failed")
	fake := mcpkey.NewErrorReader(errRand)
	m := mcpkey.NewMinterWithReader(fake)
	sk, err := m.Mint()
	if err == nil {
		t.Fatalf("Mint() with failing reader must return error; got key %q", sk.Reveal())
	}
	if !sk.IsZero() {
		t.Fatalf("Mint() with failing reader must return zero SecretKey; got %q", sk.Reveal())
	}
}

// TestMintFailClosedShortRead confirms that Mint returns an error when the
// entropy source returns fewer bytes than requested (short read).
func TestMintFailClosedShortRead(t *testing.T) {
	t.Parallel()
	// A reader that returns only 1 byte then EOF — a short read.
	fake := mcpkey.NewShortReader(1)
	m := mcpkey.NewMinterWithReader(fake)
	sk, err := m.Mint()
	if err == nil {
		t.Fatalf("Mint() with short reader must return error; got key %q", sk.Reveal())
	}
	if !sk.IsZero() {
		t.Fatalf("Mint() with short reader must return zero SecretKey")
	}
}

// TestMintUniqueness mints N keys and confirms all base62 bodies are distinct.
func TestMintUniqueness(t *testing.T) {
	t.Parallel()
	const N = 10_000
	m := mcpkey.DefaultMinter()
	seen := make(map[string]struct{}, N)
	for i := range N {
		sk, err := m.Mint()
		if err != nil {
			t.Fatalf("Mint() #%d: %v", i, err)
		}
		raw := sk.Reveal()
		if _, dup := seen[raw]; dup {
			t.Fatalf("collision at mint #%d: %q", i, raw)
		}
		seen[raw] = struct{}{}
	}
	if len(seen) != N {
		t.Fatalf("uniqueness: got %d distinct keys; want %d", len(seen), N)
	}
}

// -- helpers -----------------------------------------------------------------

// isBase62 reports whether b is a valid base62 character (0-9, A-Z, a-z).
func isBase62(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}
