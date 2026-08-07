// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package soarverify

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The canonical payload is an INTEROP commitment (ADR-0039): the signer is the
// customer's SOAR platform, an implementation we do not write. These tests pin
// the exact bytes so an independent implementation can be checked against them,
// and so a refactor cannot quietly change what a deployed playbook signs.

// mustCanonical builds the canonical payload for inputs the frozen schema
// permits, where an encoding error would be a test bug rather than a case under
// examination.
func mustCanonical(t *testing.T, scope, target, issuedAt string) []byte {
	t.Helper()
	b, err := canonicalPayload(scope, target, issuedAt)
	if err != nil {
		t.Fatalf("canonicalPayload(%q, %q, %q): %v", scope, target, issuedAt, err)
	}
	return b
}

// TestCanonicalRefusesAFieldItCannotEncode covers the uint32 length prefix's
// own bound. A field longer than the prefix can express would wrap, so two
// field sets differing by exactly 2^32 bytes would share one canonical form —
// the collision the length prefixes exist to prevent. Encoding it silently
// would be worse than refusing.
//
// The real bound is above anything a test can allocate, so the refusal is
// exercised through appendField's bound parameter. Asserting the CONSTANT's
// value instead would not bind the guard at all: deleting the length check
// would leave such a test green.
func TestCanonicalRefusesAFieldItCannotEncode(t *testing.T) {
	if _, err := appendField(nil, "target_session_id", "toolong", 4); err == nil {
		t.Error("appendField encoded a field beyond the length the prefix can " +
			"express; the prefix would wrap, so two different field sets could " +
			"share one canonical form")
	}
	// A field exactly AT the bound still encodes: an off-by-one here would
	// refuse payloads the prefix represents perfectly well.
	if _, err := appendField(nil, "target_session_id", "four", 4); err != nil {
		t.Errorf("appendField refused a field exactly at the bound: %v", err)
	}
}

// TestOverflowBoundIsTheUint32Ceiling pins the shipped bound to the largest
// length the prefix can carry. The test above proves the guard FIRES; this
// proves it fires in the right place.
func TestOverflowBoundIsTheUint32Ceiling(t *testing.T) {
	if maxFieldLen != 1<<32-1 {
		t.Errorf("maxFieldLen = %d, want %d — the largest length a uint32 prefix "+
			"expresses; lower refuses encodable fields, higher lets it wrap",
			maxFieldLen, uint64(1<<32-1))
	}
}

// TestCanonicalGoldenBytes pins the encoding against a hand-computed vector.
// A golden built by calling the function under test would agree with any
// implementation, including a wrong one; this vector is assembled from the ADR
// text instead.
func TestCanonicalGoldenBytes(t *testing.T) {
	// Hand-assembled per ADR-0039:
	//   "ocu.soar.revoke.v1" || LP("one") || LP("sess-1") || LP("2026-08-07T10:00:00Z")
	var want bytes.Buffer
	want.WriteString("ocu.soar.revoke.v1")
	for _, field := range []string{"one", "sess-1", "2026-08-07T10:00:00Z"} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		want.Write(n[:])
		want.WriteString(field)
	}

	got := mustCanonical(t, "one", "sess-1", "2026-08-07T10:00:00Z")
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("canonical payload mismatch\n got %q\nwant %q", got, want.Bytes())
	}
}

// TestCanonicalIsInjectiveAcrossFieldBoundaries is the reason ADR-0039 chose
// length prefixes over a separator. target_session_id is arbitrary text, so
// under any separator scheme two DIFFERENT field triples can serialize to one
// byte string — and a signature over one would verify the other. Each pair
// below collides under a plausible separator choice.
func TestCanonicalIsInjectiveAcrossFieldBoundaries(t *testing.T) {
	cases := []struct {
		name string
		a    [3]string
		b    [3]string
	}{
		{
			name: "target absorbs the next field under a colon separator",
			a:    [3]string{"one", "sess:2026-01-01T00:00:00Z", "x"},
			b:    [3]string{"one", "sess", "2026-01-01T00:00:00Z:x"},
		},
		{
			name: "target absorbs the next field under a newline separator",
			a:    [3]string{"one", "sess\n2026-01-01T00:00:00Z", "x"},
			b:    [3]string{"one", "sess", "2026-01-01T00:00:00Z\nx"},
		},
		{
			name: "empty target vs a scope that ends where target begins",
			a:    [3]string{"all", "", "t"},
			b:    [3]string{"al", "l", "t"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := mustCanonical(t, tc.a[0], tc.a[1], tc.a[2])
			cb := mustCanonical(t, tc.b[0], tc.b[1], tc.b[2])
			if bytes.Equal(ca, cb) {
				t.Errorf("distinct field triples produced identical canonical bytes: "+
					"%v and %v both encode to %q — a signature over one would verify "+
					"the other", tc.a, tc.b, ca)
			}
		})
	}
}

// TestCanonicalBindsTheDomainTag pins the version-bearing prefix. Without it a
// signature the SOAR key made over some other OCU payload could be replayed
// here, and a future v2 would have no unambiguous seam.
func TestCanonicalBindsTheDomainTag(t *testing.T) {
	got := mustCanonical(t, "all", "", "2026-08-07T10:00:00Z")
	if !bytes.HasPrefix(got, []byte("ocu.soar.revoke.v1")) {
		t.Errorf("canonical payload does not start with the domain tag: %q", got)
	}
}

// TestCanonicalCoversIssuedAtVerbatim pins the RFC 3339 text as sent. RFC 3339
// spells one instant several ways, so normalizing (or converting to epoch)
// would make DISTINCT wire bytes verify as equal and would force both sides to
// normalize identically.
func TestCanonicalCoversIssuedAtVerbatim(t *testing.T) {
	// Same instant, three legal spellings. Each must produce distinct bytes.
	spellings := []string{
		"2026-08-07T10:00:00Z",
		"2026-08-07T10:00:00+00:00",
		"2026-08-07T10:00:00.000Z",
	}
	seen := map[string]string{}
	for _, s := range spellings {
		enc := string(mustCanonical(t, "all", "", s))
		if prev, dup := seen[enc]; dup {
			t.Errorf("issued_at %q and %q encode identically — the signature does not "+
				"bind the representation that was sent", prev, s)
		}
		seen[enc] = s
	}
}
