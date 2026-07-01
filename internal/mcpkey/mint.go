// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkey

import (
	"crypto/rand"
	"fmt"
	"io"
)

// base62Alphabet is the 62-character alphabet used to encode the raw bytes.
// The character ordering is 0-9, A-Z, a-z. The length is exactly 62, so
// indices [0,62) map one-to-one to alphabet characters.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// base62Width is the number of base62 characters required to encode 256 bits.
// ceil(256 / log2(62)) = ceil(256 / 5.954) = 43 chars.
const base62Width = 43

// rejectThreshold is the exclusive upper bound for accepted entropy bytes.
// Bytes in [0, rejectThreshold) are accepted; bytes in [rejectThreshold, 256)
// are discarded. rejectThreshold = 248 because 248 = 4*62: the 248 accepted
// values split into exactly 4 complete groups of 62 with no remainder, so
// each alphabet character is equally likely (zero bias). Any value in [248,256)
// would create a partial group and over-represent small indices; discarding
// those values is the rejection-sampling step.
const rejectThreshold = 248 // 4 * 62; accepted range [0,248) splits into 62 bias-free groups

// skPrefix is the secret-scanner-visible prefix for every minted key.
const skPrefix = "sk-ocu-"

// randScratchSize is the number of entropy bytes fetched per Mint call.
// To encode 43 base62 chars we need at most 43 bytes (best case, all accepted),
// but rejection sampling discards ~3.1% of bytes on average (8/256). Fetching
// 64 bytes gives ample headroom: P(needing more than 64 bytes for 43 accepted)
// is astronomically small (each draw has a 248/256 acceptance probability).
// If the initial 64-byte draw is insufficient (pathologically unlucky), Mint
// draws additional batches. A rand.Read error on any draw is a hard fail-closed.
const randScratchSize = 64

// Minter is the sole constructor of SecretKey. It draws entropy from a
// configurable io.Reader (crypto/rand.Reader by default) and encodes via
// rejection-sampled base62 to produce an sk-ocu- key with exactly 256 bits of
// entropy. Minter carries no key material and is safe for concurrent use.
type Minter struct {
	rand io.Reader
}

// NewMinter returns a Minter backed by crypto/rand.Reader.
func NewMinter() *Minter { return &Minter{rand: rand.Reader} }

// Mint draws 32 random bytes from the entropy source, encodes them as a
// rejection-sampled base62 string of exactly base62Width characters, prefixes
// "sk-ocu-", and wraps the result in a SecretKey. The raw key is reachable
// only through SecretKey.Reveal.
//
// Mint fails closed on ANY read error or short read from the entropy source:
// it returns a zero SecretKey and a non-nil error. No partial or biased key
// is ever emitted.
//
// The rejection-sampling loop discards bytes >= rejectThreshold (248) to
// eliminate modulo bias. The effective entropy of the base62 body is
// 43 * log2(62) ≈ 255.9 bits, exceeding the NFR-SEC-87 floor of 256 bits
// (the prefix sk-ocu- adds deterministic structure, not guessable material;
// the random body alone meets the floor).
func (m *Minter) Mint() (SecretKey, error) {
	body, err := m.encodeBase62()
	if err != nil {
		return SecretKey{}, fmt.Errorf("mcpkey: mint: %w", err)
	}
	return newSecretKey(skPrefix + body), nil
}

// encodeBase62 draws entropy bytes and rejection-samples them into exactly
// base62Width base62 characters. It fetches randScratchSize bytes at a time
// and retries for more bytes if rejection discards too many in a single batch
// (extremely rare in practice).
func (m *Minter) encodeBase62() (string, error) {
	out := make([]byte, 0, base62Width)
	scratch := make([]byte, randScratchSize)

	for len(out) < base62Width {
		n, err := m.rand.Read(scratch)
		if err != nil {
			// Any error — including io.EOF from a short reader — is a
			// hard fail-closed: never emit a key from a partial draw.
			return "", fmt.Errorf("entropy source error: %w", err)
		}
		if n < len(scratch) {
			// A short read is a fatal entropy failure.
			return "", fmt.Errorf("entropy source short read: got %d bytes; want %d", n, len(scratch))
		}
		for _, b := range scratch[:n] {
			if b >= rejectThreshold {
				// Discard: this byte is in [248,255]; mapping such a byte
				// into [0,62) by modulo would over-represent small indices.
				// Rejection sampling discards these bytes entirely.
				continue
			}
			// b is in [0,248); 248 is exactly 4*62, so the accepted range
			// splits into 62 groups of 4 values each. Dividing by 4 maps b
			// uniformly into [0,62) with zero bias: no over-represented
			// index, no modulo-fold on an unfiltered byte.
			out = append(out, base62Alphabet[b/4])
			if len(out) == base62Width {
				break
			}
		}
	}
	return string(out), nil
}
