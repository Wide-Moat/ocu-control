// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// genesisPriorHash is the fixed prior-hash of the first event in a source's spine:
// 64 hex zeros (a SHA-256-width all-zero digest). It is a constant, not a credential;
// it anchors the chain so the first event links to a well-known, recomputable value
// rather than to nothing.
const genesisPriorHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ChainEnvelope carries one OCSF event plus its OUT-OF-BAND chain metadata: the
// per-source name, the monotonic sequence, the prior event's hash, this event's
// hash, and the canonical OCSF payload bytes. The sequence and the chain link live
// HERE, alongside the OCSF payload, never inside it — matching the audit-fanin
// contract that keeps sequence + chain metadata out-of-band from the OCSF $ref
// payload. There is no token field: Event holds only the canonical OCSFEvent bytes,
// which carry no credential.
type ChainEnvelope struct {
	// Source namespaces the sequence and the spine. A multi-source fan-in keeps
	// per-source monotonicity by this name without any source assuming a global order.
	Source string `json:"source"`
	// Sequence is the per-source MONOTONIC logical sequence, starting at 1. It is a
	// logical counter, never a timestamp: order is derived from it, not from the
	// event time, so a wall-clock setback cannot reorder the spine.
	Sequence uint64 `json:"sequence"`
	// PriorHash is the hex SHA-256 of the previous envelope in the spine, or
	// genesisPriorHash for the first. It is the tamper-evidence link.
	PriorHash string `json:"prior_hash"`
	// Hash is the hex SHA-256 over (prior_hash-bytes || uint64-BE(sequence) ||
	// canonical-event-bytes). Mutating any earlier event breaks this recompute for
	// that event and, via PriorHash, every event after it.
	Hash string `json:"hash"`
	// Event is the canonical, deterministic JSON of the OCSFEvent. It is the exact
	// byte sequence the hash was computed over, so a validator recomputes against
	// the stored bytes, not a re-marshal.
	Event json.RawMessage `json:"event"`
}

var (
	// ErrCanonicalize is the fail-closed serialization error: an OCSFEvent that
	// cannot be marshaled to canonical bytes never enters the chain.
	ErrCanonicalize = errors.New("ocsf: canonicalize event failed")

	// ErrChainInvalid is the tamper-evidence verdict: ValidateChain returns a wrapped
	// ErrChainInvalid when a recomputed hash, a broken prior-hash link, or a
	// non-monotonic sequence proves the spine was mutated.
	ErrChainInvalid = errors.New("ocsf: chain validation failed (tamper evidence)")
)

// canonicalize marshals an OCSFEvent to deterministic bytes. encoding/json emits
// struct fields in declaration order and the OCSFEvent carries no map, so the output
// is stable across calls for equal input — the property the hash relies on. A
// marshal failure is wrapped as ErrCanonicalize (it cannot occur for the fixed
// OCSFEvent shape, but the error is fail-closed rather than panicking).
func canonicalize(ev OCSFEvent) ([]byte, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCanonicalize, err)
	}
	return b, nil
}

// computeHash returns the hex SHA-256 over (prior-hash bytes || uint64-BE(sequence)
// || canonical event bytes). priorHash is the hex string of the previous event's
// hash (or genesisPriorHash); its hex DECODING is hashed so a malformed prior-hash
// is a hard error rather than silently hashing the hex text. The sequence is a
// uint64 written big-endian — no narrowing, gosec-clean.
func computeHash(priorHash string, sequence uint64, eventBytes []byte) (string, error) {
	priorBytes, err := hex.DecodeString(priorHash)
	if err != nil {
		return "", fmt.Errorf("%w: decode prior_hash: %w", ErrChainInvalid, err)
	}
	h := sha256.New()
	h.Write(priorBytes)
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], sequence)
	h.Write(seqBuf[:])
	h.Write(eventBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateChain is the tamper-evidence checker the property test drives. For each
// envelope, in order, it asserts: (a) the recomputed hash over (prior_hash ||
// sequence || event) equals the stored Hash; (b) the stored PriorHash equals the
// previous envelope's Hash (genesisPriorHash for the first); (c) the sequence is
// strictly +1 monotonic. Any failure returns a wrapped ErrChainInvalid naming the
// offending index — a single mutated byte in an earlier event breaks the recompute
// for THAT event and, via the prior-hash link, every event after it. An empty input
// is a valid (empty) chain.
func ValidateChain(envs []ChainEnvelope) error {
	prevHash := genesisPriorHash
	var prevSeq uint64
	for i, env := range envs {
		if i == 0 {
			if env.Sequence != 1 {
				return fmt.Errorf("%w: index 0 sequence = %d, want 1 (genesis)", ErrChainInvalid, env.Sequence)
			}
		} else if env.Sequence != prevSeq+1 {
			return fmt.Errorf("%w: index %d sequence = %d, want %d (not strictly monotonic)",
				ErrChainInvalid, i, env.Sequence, prevSeq+1)
		}

		// The prior-hash link check, with the marked-re-anchor exception. Normally each
		// record's PriorHash must equal the previous record's Hash (genesis for index 0).
		// A record MID-FILE whose PriorHash is genesis is a spine re-anchor: it is a
		// tamper indicator (a daemon that silently restarted the chain, or an attacker who
		// spliced a fresh segment) UNLESS the record is a legitimate chain-break marker.
		// So a mid-file genesis anchor is accepted ONLY when the event carries the
		// ChainBreak marker; a genesis anchor without it is rejected.
		reAnchored := i > 0 && env.PriorHash == genesisPriorHash
		if !reAnchored {
			if env.PriorHash != prevHash {
				return fmt.Errorf("%w: index %d prior_hash = %q, want %q (broken link)",
					ErrChainInvalid, i, env.PriorHash, prevHash)
			}
		} else {
			marker, err := chainBreakOf(env.Event)
			if err != nil {
				return fmt.Errorf("%w: index %d: %v", ErrChainInvalid, i, err)
			}
			if marker == nil {
				return fmt.Errorf("%w: index %d re-anchors the spine at genesis WITHOUT a chain-break marker "+
					"(a silent re-anchor — the spine restarted or a segment was spliced)", ErrChainInvalid, i)
			}
			if marker.ObservedPriorTip == "" {
				return fmt.Errorf("%w: index %d is a chain-break marker with an empty observed_prior_tip "+
					"(the discontinuity must record the observed tail state)", ErrChainInvalid, i)
			}
		}

		want, err := computeHash(env.PriorHash, env.Sequence, env.Event)
		if err != nil {
			return err
		}
		if want != env.Hash {
			return fmt.Errorf("%w: index %d hash = %q, recomputed %q (event mutated)",
				ErrChainInvalid, i, env.Hash, want)
		}

		prevHash = env.Hash
		prevSeq = env.Sequence
	}
	return nil
}

// chainBreakOf extracts the ChainBreak marker from an envelope's canonical event
// bytes, or nil when the event carries none. It unmarshals only the chain_break field
// (a partial decode over the fixed JSON shape), so a normal event — whose omitempty
// pointer serialized to nothing — yields nil without error.
func chainBreakOf(eventBytes json.RawMessage) (*ChainBreakInfo, error) {
	var probe struct {
		ChainBreak *ChainBreakInfo `json:"chain_break"`
	}
	if err := json.Unmarshal(eventBytes, &probe); err != nil {
		return nil, fmt.Errorf("decode event for chain_break: %w", err)
	}
	return probe.ChainBreak, nil
}
