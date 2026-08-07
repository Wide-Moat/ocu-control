// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ocsf

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// NFR-SEC-03 requires a daily Merkle head over the hash-chained spine, submitted
// to a transparency log within 24h. ADR-0009 puts the accumulator and the
// envelope signer on OCU's side of the build/buy line; the submission endpoint
// is customer-filled (#151, closed NOT_PLANNED), so this builds the head and
// stops at the envelope.
//
// A Merkle implementation has two classic ways to be wrong that a
// happy-path test never reaches, and both let an attacker present a different
// event set under a head the log already witnessed. They are pinned first.

// TestLeafAndInternalNodesAreDomainSeparated is the keystone: second-preimage
// resistance. Without distinct domain tags, an internal node's preimage
// (left||right) is indistinguishable from a leaf's, so an attacker can present
// a two-leaf subtree as a single leaf whose content is that concatenation — a
// different event set producing a head the transparency log already witnessed.
//
// The test builds the collision directly rather than asserting a tag constant,
// so it fails for a build that has tags but applies them wrongly.
func TestLeafAndInternalNodesAreDomainSeparated(t *testing.T) {
	a, b := leafDigest([]byte("event-a")), leafDigest([]byte("event-b"))

	// The head over two leaves.
	twoLeaves, err := MerkleRoot([][]byte{[]byte("event-a"), []byte("event-b")})
	if err != nil {
		t.Fatalf("two-leaf root: %v", err)
	}

	// A single "event" whose bytes ARE the internal-node preimage. Undefended,
	// its leaf hash equals the internal node above it, so the one-leaf tree
	// yields the same root as the two-leaf tree.
	forged := append(append([]byte{}, a[:]...), b[:]...)
	oneLeaf, err := MerkleRoot([][]byte{forged})
	if err != nil {
		t.Fatalf("one-leaf root: %v", err)
	}

	if twoLeaves == oneLeaf {
		t.Fatal("a single leaf carrying the internal-node preimage produced the same " +
			"head as the two events above it: leaf and internal hashing are not domain " +
			"separated, so a different event set can be presented under a witnessed head")
	}
}

// TestOddLeafCountIsUnambiguous pins the other classic hole: padding an odd
// level by duplicating its last node.
//
// The colliding pair is [x,y,z] against [x,y,z,z], NOT [x,y] against [x,y,y].
// Under duplication the three-leaf tree pads its lone tail z into N(z,z), which
// is exactly the subtree the four-leaf tree builds from its real z,z — so the
// two roots are equal and an attacker can append a duplicate of the final event
// without moving the head. Mutation testing found this: the [x,y] / [x,y,y]
// pair differs under BOTH policies, so a test using it passes against the
// vulnerable build.
func TestOddLeafCountIsUnambiguous(t *testing.T) {
	three, err := MerkleRoot([][]byte{[]byte("x"), []byte("y"), []byte("z")})
	if err != nil {
		t.Fatalf("three: %v", err)
	}
	fourDupTail, err := MerkleRoot([][]byte{[]byte("x"), []byte("y"), []byte("z"), []byte("z")})
	if err != nil {
		t.Fatalf("four: %v", err)
	}
	if three == fourDupTail {
		t.Error("[x,y,z] and [x,y,z,z] produced the same head; the odd level is padded " +
			"by duplicating its last node, so an attacker can append a copy of the " +
			"final event and still verify against the witnessed head")
	}
}

// TestOrderIsBound keeps the head sensitive to sequence. The spine is ordered by
// design (per-source monotonic sequence); a head that ignores order would let a
// replayed spine present its events rearranged.
func TestOrderIsBound(t *testing.T) {
	ab, err := MerkleRoot([][]byte{[]byte("a"), []byte("b")})
	if err != nil {
		t.Fatalf("ab: %v", err)
	}
	ba, err := MerkleRoot([][]byte{[]byte("b"), []byte("a")})
	if err != nil {
		t.Fatalf("ba: %v", err)
	}
	if ab == ba {
		t.Error("swapping two events left the head unchanged; order is not bound, so a " +
			"rearranged spine verifies against the witnessed head")
	}
}

// TestEmptyInputIsRefused fails closed. A head over nothing is not a valid
// witness of anything, and returning a fixed digest for it would let a day with
// no retained events present a well-formed head.
func TestEmptyInputIsRefused(t *testing.T) {
	if _, err := MerkleRoot(nil); !errors.Is(err, ErrNoLeaves) {
		t.Errorf("MerkleRoot(nil) error = %v, want ErrNoLeaves; a head over an empty "+
			"set witnesses nothing and must not be constructible", err)
	}
}

// TestSingleLeafRootIsItsLeafDigest pins the base case explicitly. It is the one
// tree shape with no internal node, and getting it wrong (returning the raw leaf
// bytes, or hashing a lone leaf as if it had a sibling) breaks verification for
// any day that retained exactly one event.
func TestSingleLeafRootIsItsLeafDigest(t *testing.T) {
	got, err := MerkleRoot([][]byte{[]byte("only")})
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	want := leafDigest([]byte("only"))
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("single-leaf root = %s, want the leaf digest %s",
			got, hex.EncodeToString(want[:]))
	}
}

// TestHeadOverSpineUsesEnvelopeHashes binds the accumulator to the spine it is
// supposed to witness. A head built over anything else — the event payloads, a
// re-marshal, the sequence numbers — would be a well-formed Merkle root that
// witnesses a different thing than the chain the validator checks.
func TestHeadOverSpineUsesEnvelopeHashes(t *testing.T) {
	spine := buildEnvelopes(t, 3)

	head, err := HeadOverSpine(spine)
	if err != nil {
		t.Fatalf("HeadOverSpine: %v", err)
	}

	leaves := make([][]byte, 0, len(spine))
	for _, env := range spine {
		raw, err := hex.DecodeString(env.Hash)
		if err != nil {
			t.Fatalf("decode %q: %v", env.Hash, err)
		}
		leaves = append(leaves, raw)
	}
	want, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	if head.Root != want {
		t.Errorf("head root %s is not the Merkle root over the envelope hashes (%s); "+
			"the head witnesses something other than the spine", head.Root, want)
	}
	if head.Count != uint64(len(spine)) {
		t.Errorf("head count = %d, want %d", head.Count, len(spine))
	}
	if head.Source != spine[0].Source {
		t.Errorf("head source = %q, want %q", head.Source, spine[0].Source)
	}
}

// TestHeadRefusesAMutatedSpine is the tamper-evidence property stated end to
// end. A head is a witness, so building one over a spine that does not validate
// would certify a chain the validator already rejects.
func TestHeadRefusesAMutatedSpine(t *testing.T) {
	spine := buildEnvelopes(t, 3)
	// Flip one byte of a middle event's hash: the link to its successor breaks.
	spine[1].Hash = strings.Repeat("0", 63) + "1"

	if _, err := HeadOverSpine(spine); !errors.Is(err, ErrChainInvalid) {
		t.Errorf("HeadOverSpine over a mutated spine error = %v, want ErrChainInvalid; "+
			"a head over a broken chain witnesses a spine the validator rejects", err)
	}
}

// TestHeadRefusesAMixedSourceSpine keeps the head per-source. The spine's
// monotonicity is per-source by construction, so a head spanning two sources
// would witness an order neither source guarantees.
func TestHeadRefusesAMixedSourceSpine(t *testing.T) {
	spine := buildEnvelopes(t, 2)
	spine[1].Source = spine[1].Source + "-other"

	if _, err := HeadOverSpine(spine); !errors.Is(err, ErrMixedSource) {
		t.Errorf("HeadOverSpine over two sources error = %v, want ErrMixedSource", err)
	}
}
