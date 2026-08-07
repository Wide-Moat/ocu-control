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
	"fmt"
	"math"
)

// domainTag prefixes every canonical payload. It scopes a signature to this
// surface and this revision: without it, a signature the SOAR key produced over
// some other OCU payload could be presented here, and a future revision would
// have no unambiguous seam. The version is part of the tag, so a v2
// canonicalization is a different tag rather than a reinterpretation of these
// bytes.
const domainTag = "ocu.soar.revoke.v1"

// A field longer than this cannot be encoded: the uint32 prefix would wrap, and
// two fields whose lengths differ by exactly 2^32 would then carry the SAME
// prefix — destroying the injectivity the whole scheme rests on. The frozen
// schema bounds every one of these fields far below this, so a payload reaching
// it is a caller bug rather than a legitimate revoke.
//
// Typed uint64 and compared in that domain: as an untyped constant this
// overflows int on a 32-bit build, and widening the length instead of narrowing
// the bound keeps the comparison meaningful on every architecture.
const maxFieldLen uint64 = 1<<32 - 1

// appendField writes one length-prefixed field, refusing a length the prefix
// cannot express. It takes the bound as a parameter so the refusal can be
// exercised without allocating a 4 GiB string; canonicalPayload always passes
// maxFieldLen, and nothing else calls it.
func appendField(out []byte, name, value string, bound uint64) ([]byte, error) {
	n64 := uint64(len(value))
	// Both bounds are checked, not just the caller's: a caller passing a bound
	// above the prefix ceiling would otherwise wrap the conversion below, which
	// is the failure this function exists to prevent.
	if n64 > bound || n64 > math.MaxUint32 {
		return nil, fmt.Errorf("soarverify: %s is %d bytes, beyond the %d-byte "+
			"encoding bound; the length prefix would wrap and two different field "+
			"sets could share one canonical form", name, n64, min(bound, math.MaxUint32))
	}
	var n [4]byte
	// Safe by the guard above: n64 is at or below MaxUint32.
	binary.BigEndian.PutUint32(n[:], uint32(n64))
	out = append(out, n[:]...)
	return append(out, value...), nil
}

// canonicalPayload builds the exact bytes an Ed25519 SOAR signature covers
// (ADR-0039), or reports the field that cannot be encoded:
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
func canonicalPayload(scope, target, issuedAt string) ([]byte, error) {
	fields := [...]struct {
		name  string
		value string
	}{{"scope", scope}, {"target_session_id", target}, {"issued_at", issuedAt}}

	out := make([]byte, 0, len(domainTag)+12+len(scope)+len(target)+len(issuedAt))
	out = append(out, domainTag...)
	for _, f := range fields {
		var err error
		if out, err = appendField(out, f.name, f.value, maxFieldLen); err != nil {
			return nil, err
		}
	}
	return out, nil
}
