// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"crypto"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

// The signed submission envelope carrying a daily head to a transparency log
// (NFR-SEC-03). ADR-0009 splits the signatures: OCU signs the ENVELOPE, the
// log operator signs the head. Key custody is a customer seam with a host-local
// reference default, so nothing here loads, generates, or persists a key — the
// caller supplies a crypto.Signer and owns where it came from.
//
// The submission itself is out of scope (#151): this produces the envelope and
// stops.

// headDomainTag scopes a signature to head submission. Without it, bytes the
// same key signed for another purpose could be replayed here, and a head
// signature could be replayed there. A tag shared with another context is the
// same as no tag between those two.
const headDomainTag = "ocu.audit.head.v1"

// maxHeadFieldLen bounds a length-prefixed field at what the 4-byte prefix can
// express. A longer value would wrap the prefix and alias a shorter one.
const maxHeadFieldLen uint64 = math.MaxUint32

var (
	// ErrSignatureInvalid is the verification verdict: the signature does not
	// cover this envelope's head under the given key.
	ErrSignatureInvalid = errors.New("ocsf: head envelope signature invalid")

	// ErrHeadIncomplete refuses to sign a head that witnesses nothing. A
	// well-formed envelope around an empty head would fail at the log operator
	// rather than here.
	ErrHeadIncomplete = errors.New("ocsf: head is incomplete")

	// ErrFieldTooLong refuses a value the length prefix cannot express.
	ErrFieldTooLong = errors.New("ocsf: head field exceeds the encodable length")
)

// appendHeadField writes a length-prefixed field. The prefix is what makes the
// encoding injective: without it "ab"+"cd" and "a"+"bcd" produce identical
// bytes, so one signature covers two different heads.
func appendHeadField(out []byte, value string) ([]byte, error) {
	n := uint64(len(value))
	if n > maxHeadFieldLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrFieldTooLong, n)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(n))
	out = append(out, prefix[:]...)
	return append(out, value...), nil
}

// appendHeadUint writes a fixed-width integer. Fixed width needs no prefix: 8
// bytes always, so no two values share an encoding and none can absorb a
// neighbour's bytes.
func appendHeadUint(out []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(out, b[:]...)
}

// canonicalHead builds the exact bytes a head signature covers:
//
//	headDomainTag || LP(source) || LP(root) || BE64(count)
//	              || BE64(first_sequence) || BE64(last_sequence)
//
// Every field of Head appears. A field left out is one an attacker edits freely
// on a validly signed envelope.
func canonicalHead(h Head) ([]byte, error) {
	out := []byte(headDomainTag)

	var err error
	if out, err = appendHeadField(out, h.Source); err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	if out, err = appendHeadField(out, h.Root); err != nil {
		return nil, fmt.Errorf("root: %w", err)
	}
	out = appendHeadUint(out, h.Count)
	out = appendHeadUint(out, h.FirstSequence)
	out = appendHeadUint(out, h.LastSequence)
	return out, nil
}

// HeadEnvelope is a head plus OCU's signature over it. The log operator's own
// signature over the head is added downstream and is not this struct's concern.
type HeadEnvelope struct {
	// Head is the witness being submitted, carried verbatim so a verifier
	// recomputes the canonical bytes rather than trusting a stored copy.
	Head Head `json:"head"`
	// Signature is the hex OCU signature over canonicalHead(Head).
	Signature string `json:"signature"`
}

// SignHead returns the envelope for a head, signed by the caller's key.
//
// It refuses an incomplete head: a signature over a witness of nothing is
// well-formed and useless, and the failure would otherwise surface at the log
// operator with no way back to the cause.
func SignHead(h Head, signer crypto.Signer) (HeadEnvelope, error) {
	if h.Source == "" || h.Root == "" || h.Count == 0 {
		return HeadEnvelope{}, fmt.Errorf("%w: source=%q root=%q count=%d",
			ErrHeadIncomplete, h.Source, h.Root, h.Count)
	}
	if signer == nil {
		return HeadEnvelope{}, fmt.Errorf("%w: no signer", ErrSignatureInvalid)
	}

	payload, err := canonicalHead(h)
	if err != nil {
		return HeadEnvelope{}, err
	}

	// Ed25519 signs the message itself, so the opts hash must be zero — passing
	// a hash function here makes crypto/ed25519 expect a pre-hashed digest.
	sig, err := signer.Sign(nil, payload, crypto.Hash(0))
	if err != nil {
		return HeadEnvelope{}, fmt.Errorf("sign head: %w", err)
	}

	return HeadEnvelope{Head: h, Signature: hex.EncodeToString(sig)}, nil
}

// VerifyEnvelope checks that the signature covers this envelope's head under
// pub. It recomputes the canonical bytes from the carried head, so any edit to
// any signed field breaks verification.
func VerifyEnvelope(env HeadEnvelope, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key is %d bytes, want %d",
			ErrSignatureInvalid, len(pub), ed25519.PublicKeySize)
	}
	if env.Signature == "" {
		return fmt.Errorf("%w: envelope carries no signature", ErrSignatureInvalid)
	}

	sig, err := hex.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex: %w", ErrSignatureInvalid, err)
	}

	payload, err := canonicalHead(env.Head)
	if err != nil {
		return err
	}

	// ed25519.Verify returns false for a wrong-size signature rather than
	// panicking, so no length check is needed before this call.
	if !ed25519.Verify(pub, payload, sig) {
		return ErrSignatureInvalid
	}
	return nil
}
