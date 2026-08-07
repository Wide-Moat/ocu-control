// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// NFR-SEC-03: the daily head is submitted inside an envelope OCU signs. ADR-0009
// is precise about the split — OCU signs the envelope, the transparency-log
// operator signs the head, and key CUSTODY is a customer seam with a host-local
// reference default. So the signer takes a crypto.Signer and never loads,
// generates, or persists a key.
//
// A signature over a witness is only worth the encoding underneath it. These
// pin the encoding first.

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func testHead() Head {
	return Head{
		Source:        "control-plane",
		Root:          strings.Repeat("ab", 32),
		Count:         3,
		FirstSequence: 1,
		LastSequence:  3,
	}
}

// TestEnvelopeCanonicalIsInjective is the keystone. A canonical encoding that
// concatenates fields without binding their boundaries lets two DIFFERENT heads
// produce identical bytes, so one signature verifies for both — the submitter
// signs one witness and an attacker presents another.
//
// The pairs below are chosen to collide under naive concatenation: each moves a
// character across a field boundary while leaving the joined string identical.
func TestEnvelopeCanonicalIsInjective(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b Head
	}{
		{
			name: "source and root",
			a:    Head{Source: "ab", Root: "cd", Count: 1, FirstSequence: 1, LastSequence: 1},
			b:    Head{Source: "a", Root: "bcd", Count: 1, FirstSequence: 1, LastSequence: 1},
		},
		{
			name: "empty source absorbed",
			a:    Head{Source: "", Root: "xy", Count: 1, FirstSequence: 1, LastSequence: 1},
			b:    Head{Source: "x", Root: "y", Count: 1, FirstSequence: 1, LastSequence: 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ba, err := canonicalHead(tc.a)
			if err != nil {
				t.Fatalf("canonical a: %v", err)
			}
			bb, err := canonicalHead(tc.b)
			if err != nil {
				t.Fatalf("canonical b: %v", err)
			}
			if string(ba) == string(bb) {
				t.Errorf("two distinct heads encode to identical bytes:\n  %+v\n  %+v\n"+
					"one signature then verifies for both, so a submitter signs one "+
					"witness and an attacker presents another", tc.a, tc.b)
			}
		})
	}
}

// TestEveryHeadFieldIsSigned walks the struct: changing ANY field must change
// the bytes. A field outside the signature is a field an attacker edits freely
// on a validly-signed envelope — a head whose count or range was altered still
// verifies.
func TestEveryHeadFieldIsSigned(t *testing.T) {
	base := testHead()
	baseBytes, err := canonicalHead(base)
	if err != nil {
		t.Fatalf("canonical base: %v", err)
	}

	for _, tc := range []struct {
		field  string
		mutate func(Head) Head
	}{
		{"Source", func(h Head) Head { h.Source = "other-source"; return h }},
		{"Root", func(h Head) Head { h.Root = strings.Repeat("cd", 32); return h }},
		{"Count", func(h Head) Head { h.Count = 4; return h }},
		{"FirstSequence", func(h Head) Head { h.FirstSequence = 2; return h }},
		{"LastSequence", func(h Head) Head { h.LastSequence = 4; return h }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			got, err := canonicalHead(tc.mutate(base))
			if err != nil {
				t.Fatalf("canonical mutated: %v", err)
			}
			if string(got) == string(baseBytes) {
				t.Errorf("changing %s left the signed bytes identical; the field is "+
					"outside the signature and an attacker can edit it on a validly "+
					"signed envelope", tc.field)
			}
		})
	}
}

// TestCanonicalCarriesItsDomainTag scopes the signature to this use. Without a
// tag, bytes signed for another purpose by the same key could be replayed as a
// head submission, and vice versa.
func TestCanonicalCarriesItsDomainTag(t *testing.T) {
	got, err := canonicalHead(testHead())
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if !strings.HasPrefix(string(got), headDomainTag) {
		t.Errorf("the canonical payload does not open with the domain tag %q; a "+
			"signature over it is not scoped to head submission", headDomainTag)
	}
	// The tag must not be the SOAR tag or any other context's: a shared tag is
	// the same as no tag between those two contexts.
	if !strings.Contains(headDomainTag, "audit") || !strings.Contains(headDomainTag, "head") {
		t.Errorf("domain tag %q does not name this context", headDomainTag)
	}
}

// TestSignAndVerifyRoundTrip is the happy path, kept small: the properties that
// matter are the refusals below.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	head := testHead()

	env, err := SignHead(head, priv)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := VerifyEnvelope(env, pub); err != nil {
		t.Fatalf("VerifyEnvelope on a freshly signed envelope: %v", err)
	}
	if env.Head != head {
		t.Errorf("envelope head = %+v, want %+v", env.Head, head)
	}
}

// TestVerifyRefusesATamperedHead is the property the whole envelope exists for.
// Each case edits one field of a validly signed envelope; the signature must
// stop verifying.
func TestVerifyRefusesATamperedHead(t *testing.T) {
	pub, priv := testKey(t)
	signed, err := SignHead(testHead(), priv)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}

	for _, tc := range []struct {
		field  string
		mutate func(HeadEnvelope) HeadEnvelope
	}{
		{"Root", func(e HeadEnvelope) HeadEnvelope { e.Head.Root = strings.Repeat("ff", 32); return e }},
		{"Count", func(e HeadEnvelope) HeadEnvelope { e.Head.Count = 999; return e }},
		{"Source", func(e HeadEnvelope) HeadEnvelope { e.Head.Source = "another"; return e }},
		{"LastSequence", func(e HeadEnvelope) HeadEnvelope { e.Head.LastSequence = 99; return e }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			if err := VerifyEnvelope(tc.mutate(signed), pub); !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("editing %s left the envelope verifying (err = %v); the field "+
					"is not covered, so a witnessed head can be rewritten in flight",
					tc.field, err)
			}
		})
	}
}

// TestVerifyRefusesAForeignKey pins that the signature is checked at all. A
// verifier that ignored the key would accept any envelope from anyone.
func TestVerifyRefusesAForeignKey(t *testing.T) {
	_, priv := testKey(t)
	other, _ := testKey(t)

	signed, err := SignHead(testHead(), priv)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	if err := VerifyEnvelope(signed, other); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("an envelope verified against a DIFFERENT key (err = %v)", err)
	}
}

// TestVerifyRefusesAnEmptySignature checks the outcome: an unsigned submission
// must not be indistinguishable from a signed one.
//
// The refusal alone does not bind the explicit check. An empty string
// hex-decodes to zero bytes and ed25519.Verify rejects those, so deleting the
// early return leaves this assertion green — the later check shadows it.
// Mutation testing surfaced that; TestEmptySignatureIsNamedAsSuch below binds
// the part only this guard provides.
func TestVerifyRefusesAnEmptySignature(t *testing.T) {
	pub, priv := testKey(t)
	signed, err := SignHead(testHead(), priv)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}
	signed.Signature = ""

	if err := VerifyEnvelope(signed, pub); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("an envelope with NO signature verified (err = %v); an unsigned "+
			"submission would be indistinguishable from a signed one", err)
	}
}

// TestEmptySignatureIsNamedAsSuch binds the early check to the one thing the
// generic verify failure cannot give: a diagnostic that says the envelope was
// never signed, rather than that its signature did not match.
//
// The distinction is operational. "Signature invalid" sends an operator hunting
// for a key mismatch or a tampered head; "no signature" says the signing step
// did not run, which is a different incident with a different fix.
func TestEmptySignatureIsNamedAsSuch(t *testing.T) {
	pub, priv := testKey(t)
	signed, err := SignHead(testHead(), priv)
	if err != nil {
		t.Fatalf("SignHead: %v", err)
	}

	unsigned := signed
	unsigned.Signature = ""
	absent := VerifyEnvelope(unsigned, pub)
	if absent == nil {
		t.Fatal("an unsigned envelope verified")
	}

	// A signature that is present and simply wrong, for contrast.
	wrong := signed
	wrong.Head.Root = strings.Repeat("ff", 32)
	mismatch := VerifyEnvelope(wrong, pub)
	if mismatch == nil {
		t.Fatal("a tampered envelope verified")
	}

	if absent.Error() == mismatch.Error() {
		t.Errorf("an ABSENT signature and a MISMATCHED one produce the same message "+
			"(%q); an operator cannot tell a signing step that never ran from a key "+
			"or tamper problem", absent.Error())
	}
}

// TestSignRefusesAnUnusableHead fails closed at mint time. Signing a head with
// no root produces a well-formed envelope witnessing nothing, and the failure
// would surface only at the log operator.
func TestSignRefusesAnUnusableHead(t *testing.T) {
	_, priv := testKey(t)
	for _, tc := range []struct {
		name string
		head Head
	}{
		{"no root", Head{Source: "s", Count: 1, FirstSequence: 1, LastSequence: 1}},
		{"no source", Head{Root: strings.Repeat("ab", 32), Count: 1, FirstSequence: 1, LastSequence: 1}},
		{"zero count", Head{Source: "s", Root: strings.Repeat("ab", 32), FirstSequence: 1, LastSequence: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SignHead(tc.head, priv); !errors.Is(err, ErrHeadIncomplete) {
				t.Errorf("SignHead(%s) error = %v, want ErrHeadIncomplete", tc.name, err)
			}
		})
	}
}
