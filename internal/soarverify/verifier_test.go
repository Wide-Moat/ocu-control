// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package soarverify

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-control/internal/killswitch"
	"github.com/Wide-Moat/ocu-control/internal/state"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub, priv
}

// sign produces the wire signature a conforming SOAR platform would send.
func sign(t *testing.T, priv ed25519.PrivateKey, scope, target, issuedAt string) []byte {
	t.Helper()
	return ed25519.Sign(priv, mustCanonical(t, scope, target, issuedAt))
}

func TestVerifyAcceptsAConformingSignature(t *testing.T) {
	pub, priv := mustKey(t)
	v, err := New([]Principal{{Name: "soar:splunk-prod", Tenant: "acme", Keys: []ed25519.PublicKey{pub}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload := mustCanonical(t, "one", "sess-1", "2026-08-07T10:00:00Z")
	got, err := v.Verify(context.Background(), payload, sign(t, priv, "one", "sess-1", "2026-08-07T10:00:00Z"))
	if err != nil {
		t.Fatalf("Verify rejected a conforming signature: %v", err)
	}
	want := state.Identity{Tenant: "acme", Caller: "soar:splunk-prod"}
	if got != want {
		t.Errorf("principal = %+v, want %+v — the identity must come from the "+
			"config entry whose key verified, never from the body", got, want)
	}
}

// TestVerifyRejects covers every way a call must fail, each wrapping the
// ErrSOARUnverified sentinel the fence and the 401 response depend on.
func TestVerifyRejects(t *testing.T) {
	pub, priv := mustKey(t)
	otherPub, otherPriv := mustKey(t)
	_ = otherPub

	v, err := New([]Principal{{Name: "soar:splunk-prod", Tenant: "acme", Keys: []ed25519.PublicKey{pub}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	payload := mustCanonical(t, "one", "sess-1", "2026-08-07T10:00:00Z")

	cases := []struct {
		name    string
		payload []byte
		sig     []byte
	}{
		{
			name:    "signature from a key outside the keyring",
			payload: payload,
			sig:     sign(t, otherPriv, "one", "sess-1", "2026-08-07T10:00:00Z"),
		},
		{
			name:    "signature over different fields than the payload presents",
			payload: payload,
			sig:     sign(t, priv, "one", "sess-2", "2026-08-07T10:00:00Z"),
		},
		{
			name:    "empty signature",
			payload: payload,
			sig:     nil,
		},
		{
			name:    "truncated signature",
			payload: payload,
			sig:     sign(t, priv, "one", "sess-1", "2026-08-07T10:00:00Z")[:32],
		},
		{
			name:    "valid signature presented over a tampered payload",
			payload: mustCanonical(t, "all", "", "2026-08-07T10:00:00Z"),
			sig:     sign(t, priv, "one", "sess-1", "2026-08-07T10:00:00Z"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v.Verify(context.Background(), tc.payload, tc.sig)
			if err == nil {
				t.Fatalf("Verify ACCEPTED %s — the fence would mint a scope for an "+
					"unverified caller", tc.name)
			}
			if !errors.Is(err, killswitch.ErrSOARUnverified) {
				t.Errorf("error %v does not wrap ErrSOARUnverified; the operator "+
					"adapter keys its 401 on that sentinel", err)
			}
			if (got != state.Identity{}) {
				t.Errorf("Verify returned identity %+v on a refusal, want the zero "+
					"value — a non-zero identity on a failed verify is a mintable scope", got)
			}
		})
	}
}

// TestMalformedSignatureIsDistinguishableFromAForgedOne pins the one thing the
// signature-length guard buys. ed25519.Verify returns false for ANY signature
// length rather than panicking, so removing the guard still refuses the call —
// what it loses is the operator's ability to tell a malformed webhook (an
// integration bug) from a forged one (an attack), which need different
// responses. Without this test the guard is unprotected: deleting it changes
// only an error string, and no other test reads that string.
func TestMalformedSignatureIsDistinguishableFromAForgedOne(t *testing.T) {
	pub, priv := mustKey(t)
	v, err := New([]Principal{{Name: "soar:x", Tenant: "t", Keys: []ed25519.PublicKey{pub}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	payload := mustCanonical(t, "all", "", "2026-08-07T10:00:00Z")

	_, malformed := v.Verify(context.Background(), payload, []byte{1, 2, 3})
	// A well-formed signature from a key that is simply not on the keyring.
	_, otherPriv := mustKey(t)
	_, forged := v.Verify(context.Background(), payload, ed25519.Sign(otherPriv, payload))
	_ = priv

	if malformed == nil || forged == nil {
		t.Fatal("both calls must be refused")
	}
	if malformed.Error() == forged.Error() {
		t.Errorf("a malformed signature and a forged one produce the same error %q; "+
			"an operator cannot tell an integration bug from an attack", malformed)
	}
}

// TestVerifySelectsThePrincipalWhoseKeyVerified pins that the returned identity
// tracks the verifying key across a multi-principal keyring. A verifier that
// returned the first configured entry would pass a single-principal test and
// attribute every revoke to the wrong actor in a real deployment.
func TestVerifySelectsThePrincipalWhoseKeyVerified(t *testing.T) {
	pubA, _ := mustKey(t)
	pubB, privB := mustKey(t)

	v, err := New([]Principal{
		{Name: "soar:first", Tenant: "t1", Keys: []ed25519.PublicKey{pubA}},
		{Name: "soar:second", Tenant: "t2", Keys: []ed25519.PublicKey{pubB}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload := mustCanonical(t, "all", "", "2026-08-07T10:00:00Z")
	got, err := v.Verify(context.Background(), payload, ed25519.Sign(privB, payload))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := state.Identity{Tenant: "t2", Caller: "soar:second"}
	if got != want {
		t.Errorf("principal = %+v, want %+v — the actor must be the entry whose "+
			"key verified, not the first configured one", got, want)
	}
}

// TestVerifyAcceptsEitherKeyDuringRotation pins the overlap window: an entry
// may carry the outgoing and incoming key at once so a SOAR platform can rotate
// without a refusal gap.
func TestVerifyAcceptsEitherKeyDuringRotation(t *testing.T) {
	oldPub, oldPriv := mustKey(t)
	newPub, newPriv := mustKey(t)

	v, err := New([]Principal{{
		Name: "soar:rotating", Tenant: "acme",
		Keys: []ed25519.PublicKey{oldPub, newPub},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	payload := mustCanonical(t, "all", "", "2026-08-07T10:00:00Z")

	for name, priv := range map[string]ed25519.PrivateKey{"outgoing": oldPriv, "incoming": newPriv} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), payload, ed25519.Sign(priv, payload)); err != nil {
				t.Errorf("Verify rejected the %s key during rotation overlap: %v", name, err)
			}
		})
	}
}

// TestNewRejectsAnUnusableKeyring fails construction rather than at the first
// revoke. A verifier built from a keyring that can never verify anything would
// refuse every call at the worst possible moment — during an incident.
func TestNewRejectsAnUnusableKeyring(t *testing.T) {
	pub, _ := mustKey(t)
	cases := []struct {
		name       string
		principals []Principal
	}{
		{name: "no principals", principals: nil},
		{name: "principal with no keys", principals: []Principal{{Name: "soar:x", Tenant: "t"}}},
		{name: "principal with no name", principals: []Principal{{Tenant: "t", Keys: []ed25519.PublicKey{pub}}}},
		{
			name:       "key of the wrong size",
			principals: []Principal{{Name: "soar:x", Tenant: "t", Keys: []ed25519.PublicKey{{1, 2, 3}}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.principals); err == nil {
				t.Errorf("New accepted an unusable keyring (%s); the failure would "+
					"surface as a refused revoke during an incident instead", tc.name)
			}
		})
	}
}

// TestVerifierSatisfiesTheKillswitchInterface binds this implementation to the
// seam the fence takes. Without it the package could drift out of the interface
// and only a wiring commit would notice.
func TestVerifierSatisfiesTheKillswitchInterface(t *testing.T) {
	pub, _ := mustKey(t)
	v, err := New([]Principal{{Name: "soar:x", Tenant: "t", Keys: []ed25519.PublicKey{pub}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var _ killswitch.SOARVerifier = v
}
