// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/audit/ocsf"
)

// `occ audit head` composes the pieces NFR-SEC-03 puts on OCU's side: read the
// retained spine, validate it, accumulate the daily Merkle head, and sign the
// submission envelope. The submission itself is a customer seam (#151), so this
// writes the envelope and stops.
//
// It is the operator-runnable form of the daily job, which is why the failure
// modes below matter more than the happy path: an envelope that is produced
// when it should not be is worse than one that is missing.

// writeSigningKey writes a PKCS#8 Ed25519 private key and returns its path plus
// the public half for verification.
func writeSigningKey(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "head-signing.key")
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path, pub
}

// Test_AuditHead_SignsAVerifiableEnvelope is the end-to-end property: what the
// command writes must verify against the operator's public key, and its head
// must be the one the spine actually produces.
func Test_AuditHead_SignsAVerifiableEnvelope(t *testing.T) {
	t.Parallel()
	spine := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, spine, 4)
	keyPath, pub := writeSigningKey(t)

	var out bytes.Buffer
	if err := run(context.Background(),
		[]string{"audit", "head", "--file", spine, "--signing-key", keyPath},
		&out, unixHTTPClient); err != nil {
		t.Fatalf("occ audit head = %v, want nil", err)
	}

	var env ocsf.HeadEnvelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("output is not a HeadEnvelope: %v\n%s", err, out.String())
	}
	if err := ocsf.VerifyEnvelope(env, pub); err != nil {
		t.Fatalf("the emitted envelope does not verify against the signing key: %v", err)
	}

	// The head must witness THIS spine, not a well-formed head over something
	// else. Recompute independently from the file.
	envs, err := ocsf.ReadChainFile(spine)
	if err != nil {
		t.Fatalf("ReadChainFile: %v", err)
	}
	want, err := ocsf.HeadOverSpine(envs)
	if err != nil {
		t.Fatalf("HeadOverSpine: %v", err)
	}
	if env.Head != want {
		t.Errorf("emitted head %+v does not match the head over the spine %+v",
			env.Head, want)
	}
	if env.Head.Count != 4 {
		t.Errorf("head covers %d events, the spine holds 4", env.Head.Count)
	}
}

// Test_AuditHead_RefusesATamperedSpine is the keystone refusal. A head is a
// witness; emitting one over a chain that fails validation would sign a
// statement the verifier already rejects, and the transparency log would then
// hold OCU's signature over a broken spine.
func Test_AuditHead_RefusesATamperedSpine(t *testing.T) {
	t.Parallel()
	spine := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, spine, 3)
	keyPath, _ := writeSigningKey(t)

	// Flip a byte inside the middle event's payload: the recomputed hash no
	// longer matches, exactly as the verify command's tamper case does.
	raw, err := os.ReadFile(spine)
	if err != nil {
		t.Fatalf("read spine: %v", err)
	}
	mutated := bytes.Replace(raw, []byte(`"reason":""`), []byte(`"reason":"x"`), 1)
	if bytes.Equal(raw, mutated) {
		t.Fatal("the mutation did not apply; this test would pass vacuously")
	}
	if err := os.WriteFile(spine, mutated, 0o600); err != nil {
		t.Fatalf("write mutated spine: %v", err)
	}

	var out bytes.Buffer
	err = run(context.Background(),
		[]string{"audit", "head", "--file", spine, "--signing-key", keyPath},
		&out, unixHTTPClient)
	if err == nil {
		t.Fatal("occ audit head signed a head over a TAMPERED spine; the log would " +
			"hold OCU's signature over a chain the verifier rejects")
	}
	if out.Len() != 0 {
		t.Errorf("a refused run still wrote %d bytes of output; a partial envelope on "+
			"stdout could be piped onward as if it were valid", out.Len())
	}

	// The refusal must name the tamper. Discarding HeadOverSpine's error still
	// fails the run — SignHead rejects the resulting zero-value head — so the
	// non-nil check above does not bind the validation step. Mutation testing
	// surfaced that. An operator told "head is incomplete" for a tampered spine
	// looks for a retention or scheduling fault, not for a mutated audit file.
	if !errors.Is(err, ocsf.ErrChainInvalid) {
		t.Errorf("the refusal is %v, which does not identify a tamper; the chain "+
			"validation result is being swallowed and something downstream is "+
			"refusing for an unrelated reason", err)
	}
}

// Test_AuditHead_RefusesAnEmptySpine fails closed on a file with no events. A
// head over nothing witnesses nothing, and emitting one would let a period that
// retained no events present a well-formed submission.
func Test_AuditHead_RefusesAnEmptySpine(t *testing.T) {
	t.Parallel()
	spine := filepath.Join(t.TempDir(), "empty.ocsf.jsonl")
	if err := os.WriteFile(spine, nil, 0o600); err != nil {
		t.Fatalf("write empty spine: %v", err)
	}
	keyPath, _ := writeSigningKey(t)

	var out bytes.Buffer
	if err := run(context.Background(),
		[]string{"audit", "head", "--file", spine, "--signing-key", keyPath},
		&out, unixHTTPClient); err == nil {
		t.Fatal("occ audit head emitted an envelope for a spine with no events")
	}
}

// Test_AuditHead_RequiresBothFlags keeps each flag separately required. The two
// checks run in sequence, so omitting one is caught by the next as well — a
// single case supplying neither proves only that SOME guard exists, and either
// could then be deleted while the suite stayed green.
func Test_AuditHead_RequiresBothFlags(t *testing.T) {
	t.Parallel()
	spine := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, spine, 2)
	keyPath, _ := writeSigningKey(t)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no file", []string{"audit", "head", "--signing-key", keyPath}, "--file"},
		{"no key", []string{"audit", "head", "--file", spine}, "--signing-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(context.Background(), tc.args, &out, unixHTTPClient)
			if err == nil {
				t.Fatalf("occ audit head ran with %s missing", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("omitting %s was refused by a DIFFERENT guard (%v); this "+
					"assertion is not bound to the one it names", tc.want, err)
			}
		})
	}
}

// Test_AuditHead_RefusesANonEd25519Key names the mismatch rather than emitting
// an envelope no verifier can check. ADR-0009 leaves key custody to the
// deployment, so the key file is operator-supplied and its type is not
// guaranteed.
func Test_AuditHead_RefusesANonEd25519Key(t *testing.T) {
	t.Parallel()
	spine := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, spine, 2)

	// A key that parses as PKCS#8 but is not Ed25519. Generated rather than
	// embedded: a hard-coded private key in the tree is a secret-scanner hit
	// whatever its provenance.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ec.key")
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	var out bytes.Buffer
	err = run(context.Background(),
		[]string{"audit", "head", "--file", spine, "--signing-key", path},
		&out, unixHTTPClient)
	if err == nil {
		t.Fatal("occ audit head accepted a non-Ed25519 signing key")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ed25519") {
		t.Errorf("the refusal does not name the expected key type: %v", err)
	}
}

// Test_AuditHead_UnknownVerb keeps the dispatch honest: a typo must not fall
// through to a verb that does something else.
func Test_AuditHead_UnknownVerb(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	err := run(context.Background(), []string{"audit", "heads"}, &out, unixHTTPClient)
	if err == nil {
		t.Fatal("occ audit heads was accepted")
	}
	if !strings.Contains(err.Error(), "heads") {
		t.Errorf("the error does not name the unknown verb: %v", err)
	}
}

// Test_AuditHead_OutputIsTheEnvelopeAlone keeps stdout machine-readable. The
// command exists to be piped at a submission step, so a human-facing preamble
// would break every consumer.
func Test_AuditHead_OutputIsTheEnvelopeAlone(t *testing.T) {
	t.Parallel()
	spine := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	writeAuditFile(t, spine, 2)
	keyPath, _ := writeSigningKey(t)

	var out bytes.Buffer
	if err := run(context.Background(),
		[]string{"audit", "head", "--file", spine, "--signing-key", keyPath},
		&out, unixHTTPClient); err != nil {
		t.Fatalf("occ audit head = %v", err)
	}

	trimmed := strings.TrimSpace(out.String())
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("stdout is not a bare JSON object; a consumer piping this cannot "+
			"parse it:\n%s", out.String())
	}
	// The signature must be hex, not raw bytes: the envelope crosses a pipe.
	var env ocsf.HeadEnvelope
	if err := json.Unmarshal([]byte(trimmed), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := hex.DecodeString(env.Signature); err != nil {
		t.Errorf("signature %q is not hex: %v", env.Signature, err)
	}
}
