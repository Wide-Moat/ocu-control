// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package jwks_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/cred"
	"github.com/Wide-Moat/ocu-control/internal/jwks"
)

// readSet reads the written artifact file and unmarshals it back into a jwks.Set,
// failing the test on a read or parse error — the round-trip the deploy layer / the
// edge performs when it fetches the served document.
func readSet(t *testing.T, path string) jwks.Set {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact %q: %v", path, err)
	}
	var set jwks.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("artifact bytes do not parse as a JWKS Set: %v\n%s", err, raw)
	}
	return set
}

// TestWriteArtifactRendersValidJWKS proves that for BOTH algs the written bytes
// parse as a valid JWKS carrying the signer's single active public key with the
// right kid/alg and the coordinate the alg requires (x for OKP, x+y for EC).
func TestWriteArtifactRendersValidJWKS(t *testing.T) {
	t.Parallel()
	for _, alg := range []cred.Alg{cred.AlgEdDSA, cred.AlgES256} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			signer, _ := newSigner(t, alg)
			path := filepath.Join(t.TempDir(), "jwks.json")
			if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
				t.Fatalf("WriteArtifact: %v", err)
			}
			set := readSet(t, path)
			if len(set.Keys) != 1 {
				t.Fatalf("artifact has %d keys, want 1", len(set.Keys))
			}
			k := set.Keys[0]
			if k.Kid != signer.ActiveKID() {
				t.Fatalf("artifact kid %q != active kid %q", k.Kid, signer.ActiveKID())
			}
			if k.Alg != alg.JWTMethod() {
				t.Fatalf("artifact alg %q != %q", k.Alg, alg.JWTMethod())
			}
			if k.Use != "sig" {
				t.Fatalf("artifact use %q, want sig", k.Use)
			}
			if k.X == "" {
				t.Fatal("artifact JWK missing x coordinate")
			}
			if alg == cred.AlgES256 && k.Y == "" {
				t.Fatal("EC artifact JWK missing y coordinate")
			}
			if alg == cred.AlgEdDSA && k.Y != "" {
				t.Fatalf("OKP artifact JWK carries a y coordinate %q; want absent", k.Y)
			}
		})
	}
}

// TestWriteArtifactWireBytesNoPrivateMaterial is the custody assertion at the WIRE:
// for both algs it reads the written file as raw bytes and asserts none of the
// private-JWK member keys appears. It matches the quoted key with its colon (e.g.
// `"d":`) so a base64 coordinate that merely contains the letter d is not a false
// hit. This proves custody against the bytes the deploy layer would serve,
// independent of the JWK struct's current shape.
func TestWriteArtifactWireBytesNoPrivateMaterial(t *testing.T) {
	t.Parallel()
	forbidden := []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`}
	for _, alg := range []cred.Alg{cred.AlgEdDSA, cred.AlgES256} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			signer, _ := newSigner(t, alg)
			path := filepath.Join(t.TempDir(), "jwks.json")
			if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
				t.Fatalf("WriteArtifact: %v", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read artifact: %v", err)
			}
			for _, f := range forbidden {
				if bytes.Contains(raw, []byte(f)) {
					t.Fatalf("served JWKS bytes contain private-key member %s — custody leak:\n%s", f, raw)
				}
			}
		})
	}
}

// TestWriteArtifactEmptyKeySetFailsClosed proves the package-level fail-closed
// fence: both a nil and an empty slice return ErrEmptyKeySet and write NO file (an
// empty JWKS would make the edge reject every token / mask a missing signer).
func TestWriteArtifactEmptyKeySetFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pub  []cred.PublicKey
	}{
		{"nil", nil},
		{"empty", []cred.PublicKey{}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "jwks.json")
			err := jwks.WriteArtifact(path, tc.pub)
			if !errors.Is(err, jwks.ErrEmptyKeySet) {
				t.Fatalf("WriteArtifact(%s) = %v, want ErrEmptyKeySet", tc.name, err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("WriteArtifact(%s) wrote a file on an empty set (stat err=%v); want no file", tc.name, statErr)
			}
		})
	}
}

// TestWriteArtifactRefusesUnrenderableKey proves WriteArtifact propagates Publish's
// fail-closed ErrUnsupportedKey and writes NO file: an unrenderable key is never
// silently omitted and never leaves a partial/empty artifact behind.
func TestWriteArtifactRefusesUnrenderableKey(t *testing.T) {
	t.Parallel()
	signer, _ := newSigner(t, cred.AlgEdDSA)
	good := signer.PublicKeys()[0]
	// An unknown alg the publisher cannot render (mirrors publish_errors_test.go).
	bad := cred.PublicKey{KID: "k-bad", Alg: cred.Alg(99), Pub: good.Pub}

	path := filepath.Join(t.TempDir(), "jwks.json")
	err := jwks.WriteArtifact(path, []cred.PublicKey{good, bad})
	if !errors.Is(err, jwks.ErrUnsupportedKey) {
		t.Fatalf("WriteArtifact with an unrenderable key = %v, want ErrUnsupportedKey", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("WriteArtifact left a file after an unrenderable-key refusal (stat err=%v); want no file", statErr)
	}
}

// TestWriteArtifactAtomic proves the write is temp+rename, never in-place:
//
//	(a) a write whose rename cannot land (the destination path is a directory, so
//	    os.Rename over it fails) leaves a PRE-EXISTING valid artifact intact — a
//	    reader never sees a half-written or truncated Set; and
//	(b) no stray .tmp-jwks-* temp file survives either a successful write or a
//	    failed one (the deferred cleanup ran), which is only true if the write goes
//	    through a temp file and renames it into place.
func TestWriteArtifactAtomic(t *testing.T) {
	t.Parallel()
	signer, _ := newSigner(t, cred.AlgEdDSA)
	dir := t.TempDir()

	// (a) Pre-place an OLD valid artifact, then force the rename to fail by making
	// the destination a directory (rename of a file over a non-empty directory
	// fails). The OLD file must remain intact and parseable.
	oldPath := filepath.Join(dir, "old-jwks.json")
	if err := jwks.WriteArtifact(oldPath, signer.PublicKeys()); err != nil {
		t.Fatalf("seed old artifact: %v", err)
	}
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read seeded artifact: %v", err)
	}

	destDir := filepath.Join(dir, "dest-is-a-dir")
	if err := os.Mkdir(destDir, 0o755); err != nil {
		t.Fatalf("mkdir dest dir: %v", err)
	}
	// A non-empty directory: os.Rename(tmpFile, destDir) fails on every platform.
	if err := os.WriteFile(filepath.Join(destDir, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatalf("occupy dest dir: %v", err)
	}
	if err := jwks.WriteArtifact(destDir, signer.PublicKeys()); err == nil {
		t.Fatal("WriteArtifact over a non-empty directory should fail the rename")
	}
	// The OLD, separate artifact is untouched and still parses — an interrupted
	// write never corrupts an existing served document.
	nowBytes, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("re-read old artifact after a failed write: %v", err)
	}
	if !bytes.Equal(oldBytes, nowBytes) {
		t.Fatal("a failed WriteArtifact mutated an unrelated existing artifact")
	}

	// (b) No leftover temp files in dir after the successful seed write and the
	// failed write — proving the write is temp+rename, never written-in-place.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-jwks-") {
			t.Fatalf("a temp file %q survived; the atomic write did not clean up", e.Name())
		}
	}
}

// TestWriteArtifactConcurrentReaderNeverPartial hammers a reader against repeated
// re-renders over the SAME path: every successful read parses as a complete JWKS.
// The rename-based write guarantees a reader observes the OLD or the NEW complete
// file, never a half-written Set.
func TestWriteArtifactConcurrentReaderNeverPartial(t *testing.T) {
	t.Parallel()
	signer, _ := newSigner(t, cred.AlgEdDSA)
	path := filepath.Join(t.TempDir(), "jwks.json")
	// Seed so the reader always has a file to open.
	if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
				t.Errorf("re-render %d: %v", i, err)
				return
			}
		}
		close(stop)
	}()

	for {
		select {
		case <-stop:
			wg.Wait()
			return
		default:
			raw, err := os.ReadFile(path)
			if err != nil {
				// A transient ENOENT is impossible here (rename is atomic and the dest
				// always exists after the seed), so any read error is a real fault.
				t.Fatalf("concurrent read: %v", err)
			}
			var set jwks.Set
			if err := json.Unmarshal(raw, &set); err != nil {
				t.Fatalf("concurrent reader saw a partial/unparseable Set: %v\n%s", err, raw)
			}
			if len(set.Keys) == 0 {
				t.Fatalf("concurrent reader saw an empty Set:\n%s", raw)
			}
		}
	}
}

// TestWriteArtifactRotationFaithful proves the rendered Set reflects the signer's
// CURRENT PublicKeys() across a rotation window, and that each re-render is atomic
// over the same destination. It mirrors TestOverlapPublishesBothThenDrops: render
// (1 active key) -> rotate -> re-render (2 keys: new active + previous in overlap)
// -> advance past the 24h overlap -> re-render (1 key, previous dropped).
func TestWriteArtifactRotationFaithful(t *testing.T) {
	signer, clk := newSigner(t, cred.AlgEdDSA)
	path := filepath.Join(t.TempDir(), "jwks.json")

	// 1. Initial render: the single active key.
	origKID := signer.ActiveKID()
	if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
		t.Fatalf("initial WriteArtifact: %v", err)
	}
	set := readSet(t, path)
	if len(set.Keys) != 1 {
		t.Fatalf("initial artifact has %d keys, want 1", len(set.Keys))
	}
	if set.Keys[0].Kid != origKID {
		t.Fatalf("initial artifact kid %q != active kid %q", set.Keys[0].Kid, origKID)
	}

	// 2. Rotate, then re-render over the SAME path: both keys publish in the overlap.
	newKey := freshEd25519Signer(t)
	signer.KeySet().Rotate(newKey, cred.AlgEdDSA, "kid-rotated-2")
	newKID := signer.ActiveKID()
	if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
		t.Fatalf("overlap re-render: %v", err)
	}
	set2 := readSet(t, path)
	if len(set2.Keys) != 2 {
		t.Fatalf("overlap artifact has %d keys, want 2 (active + previous)", len(set2.Keys))
	}
	kids := map[string]bool{}
	for _, k := range set2.Keys {
		kids[k.Kid] = true
	}
	if !kids[newKID] {
		t.Fatalf("overlap artifact missing the NEW active kid %q", newKID)
	}
	if !kids[origKID] {
		t.Fatalf("overlap artifact missing the PREVIOUS kid %q", origKID)
	}

	// 3. Advance past the 24h overlap window, re-render: the previous key drops.
	clk.Advance(25 * time.Hour)
	if err := jwks.WriteArtifact(path, signer.PublicKeys()); err != nil {
		t.Fatalf("post-overlap re-render: %v", err)
	}
	set3 := readSet(t, path)
	if len(set3.Keys) != 1 {
		t.Fatalf("post-overlap artifact has %d keys, want 1 (previous dropped)", len(set3.Keys))
	}
	if set3.Keys[0].Kid != newKID {
		t.Fatalf("post-overlap artifact kid %q != current active kid %q", set3.Keys[0].Kid, newKID)
	}
}

// TestArtifactNoNetImport is the no-third-listener fence as a COMPILE FACT: it
// parses internal/jwks/artifact.go and asserts its import set contains neither
// "net" nor "net/http". The artifact emitter is a pure file writer — it opens no
// listener and serves nothing; the deploy layer serves the file. The assertion is
// scoped to the file this change adds, so pre-existing test scaffolding elsewhere
// (e.g. the operator /healthz probe's net/http) is not in scope.
func TestArtifactNoNetImport(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	// The test runs with its working directory at the package dir, so artifact.go is
	// a sibling on disk.
	f, err := parser.ParseFile(fset, "artifact.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse artifact.go: %v", err)
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if path == "net" || path == "net/http" {
			t.Fatalf("artifact.go imports %q — the artifact emitter must add NO network surface", path)
		}
	}
}
