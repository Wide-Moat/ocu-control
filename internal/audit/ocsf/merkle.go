// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// The daily Merkle head over a source's hash-chained spine (NFR-SEC-03).
// ADR-0009 puts the accumulator and the envelope signer on OCU's side of the
// build/buy line; the transparency-log endpoint the head is submitted to is
// customer-filled, so nothing here dials anything.
//
// The head witnesses the SPINE, not the payloads: its leaves are the chain
// envelope hashes, which are what ValidateChain recomputes. A head over the
// event bytes would be a well-formed Merkle root witnessing a different thing
// than the validator checks.

const (
	// leafPrefix and nodePrefix domain-separate the two hash inputs, following
	// RFC 6962. Without them a leaf's preimage and an internal node's preimage
	// are the same shape, so a single leaf carrying the bytes (left||right) of
	// an internal node hashes to that node — presenting a different event set
	// under a head the log already witnessed. This is the second-preimage
	// attack, and it is a property of the construction, not of SHA-256.
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

var (
	// ErrNoLeaves refuses a head over an empty set. Such a head witnesses
	// nothing, and a fixed digest for the empty case would let a period that
	// retained no events present a well-formed head.
	ErrNoLeaves = errors.New("ocsf: merkle head over an empty leaf set")

	// ErrMixedSource refuses a head spanning more than one source. Sequence
	// monotonicity is per-source, so a head over two spines would witness an
	// order neither source guarantees.
	ErrMixedSource = errors.New("ocsf: merkle head over more than one source")
)

// leafDigest hashes one leaf under the leaf domain tag.
func leafDigest(b []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(b)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// nodeDigest hashes two child digests under the internal-node domain tag.
func nodeDigest(l, r [sha256.Size]byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(l[:])
	h.Write(r[:])
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot computes the RFC 6962 root over leaves, in the order given, and
// returns it hex-encoded.
//
// An odd level PROMOTES its last node unchanged rather than duplicating it.
// Duplication is the other classic hole: it makes [x, y, y] and [x, y] collide,
// so a trailing event could be added or removed without moving the head.
func MerkleRoot(leaves [][]byte) (string, error) {
	if len(leaves) == 0 {
		return "", ErrNoLeaves
	}

	level := make([][sha256.Size]byte, 0, len(leaves))
	for _, l := range leaves {
		level = append(level, leafDigest(l))
	}

	for len(level) > 1 {
		next := make([][sha256.Size]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// Odd tail: promote, never duplicate.
				next = append(next, level[i])
				continue
			}
			next = append(next, nodeDigest(level[i], level[i+1]))
		}
		level = next
	}

	return hex.EncodeToString(level[0][:]), nil
}

// Head is the daily witness over one source's spine. It carries what a verifier
// needs to recompute the root from the spine it holds, and nothing that a
// signature would have to cover twice.
type Head struct {
	// Source is the spine this head witnesses. A head is per-source because
	// sequence monotonicity is.
	Source string `json:"source"`
	// Root is the hex Merkle root over the spine's envelope hashes.
	Root string `json:"root"`
	// Count is how many envelopes the root covers. A verifier that recomputes a
	// matching root over a different number of leaves has found a truncation.
	Count uint64 `json:"count"`
	// FirstSequence and LastSequence bound the covered range, so two consecutive
	// heads can be checked for a gap without re-reading either spine.
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
}

// HeadOverSpine validates the spine and returns the head that witnesses it.
//
// Validation is not a convenience: a head is a witness, and building one over a
// chain the validator rejects would certify a spine already known to be broken.
func HeadOverSpine(envs []ChainEnvelope) (Head, error) {
	if len(envs) == 0 {
		return Head{}, ErrNoLeaves
	}

	source := envs[0].Source
	for i, env := range envs {
		if env.Source != source {
			return Head{}, fmt.Errorf("%w: envelope %d is %q, the spine opened with %q",
				ErrMixedSource, i, env.Source, source)
		}
	}

	if err := ValidateChain(envs); err != nil {
		return Head{}, err
	}

	leaves := make([][]byte, 0, len(envs))
	for i, env := range envs {
		raw, err := hex.DecodeString(env.Hash)
		if err != nil {
			return Head{}, fmt.Errorf("%w: envelope %d hash %q is not hex: %w",
				ErrChainInvalid, i, env.Hash, err)
		}
		leaves = append(leaves, raw)
	}

	root, err := MerkleRoot(leaves)
	if err != nil {
		return Head{}, err
	}

	return Head{
		Source:        source,
		Root:          root,
		Count:         uint64(len(envs)),
		FirstSequence: envs[0].Sequence,
		LastSequence:  envs[len(envs)-1].Sequence,
	}, nil
}
