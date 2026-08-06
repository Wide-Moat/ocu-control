// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package soarverify implements the minimal-shelf SOAR webhook verifier
// (ADR-0039): an Ed25519 signature over a length-prefixed canonical payload,
// checked against a host-owned keyring supplied as configuration.
//
// The verifier is a pure signature check. The issued_at acceptance window and
// the seen-signature cache live in the operator adapter, NOT here, so a
// deployment that swaps this verifier for the full-shelf SVID one cannot lose
// replay protection by construction.
package soarverify

import (
	"encoding/binary"
)

// domainTag prefixes every canonical payload. It scopes a signature to this
// surface and this revision: without it, a signature the SOAR key produced over
// some other OCU payload could be presented here, and a future revision would
// have no unambiguous seam. The version is part of the tag, so a v2
// canonicalization is a different tag rather than a reinterpretation of these
// bytes.
const domainTag = "ocu.soar.revoke.v1"

// canonicalPayload builds the exact bytes an Ed25519 SOAR signature covers
// (ADR-0039):
//
//	canonical = domainTag || LP(scope) || LP(target) || LP(issuedAt)
//	LP(s)     = uint32 big-endian byte-length of s, then the UTF-8 bytes of s
//
// The arguments are the DECODED JSON string values of the SoarRevokeRequest
// fields, not the raw JSON source: signing raw body bytes would force
// byte-identical serializers on both sides, and the signer builds these values
// before it encodes them.
//
// target is the empty string when scope is "all" (the frozen schema forbids the
// field in that case). issuedAt is the RFC 3339 text VERBATIM — no epoch
// conversion and no normalization, because RFC 3339 spells one instant several
// ways and converting would make distinct wire bytes verify as equal.
//
// The length prefixes are what make the encoding injective. target_session_id
// is arbitrary text up to the schema bound, so under any separator scheme two
// distinct field triples can serialize to one byte string, and a signature over
// one would verify the other.
func canonicalPayload(scope, target, issuedAt string) []byte {
	out := make([]byte, 0, len(domainTag)+12+len(scope)+len(target)+len(issuedAt))
	out = append(out, domainTag...)
	for _, field := range [...]string{scope, target, issuedAt} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		out = append(out, n[:]...)
		out = append(out, field...)
	}
	return out
}
