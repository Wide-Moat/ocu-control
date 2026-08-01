// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package lifecycle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// scopeHandleVersion prefixes the scope-handle derivation pre-image so a future
// change to the scheme is distinguishable and a suffix minted under an earlier
// scheme never collides with one minted under a later scheme. It doubles as the
// domain separator (no salt): the version tag is the only thing distinguishing
// this hash domain from the session-key or handle-mint domains that share the
// length-prefix shape.
const scopeHandleVersion = "ocu-scope-v1"

// scopeHandleHexLen is the truncated width of the derived suffix: the first 16
// lowercase-hex characters of the SHA-256 digest. It fixes the derivation
// alphabet so the north-face shape guard and the filestore scope-source can
// recognise a derived scope by the "<base>-[0-9a-f]{16}" pattern.
const scopeHandleHexLen = 16

// scopeHandle derives the per-chat storage-scope suffix from the host-resolved
// owner Identity and the chat handle. It folds a version tag and each of Tenant,
// Caller, and handle into a length-prefixed pre-image (the same writeField shape
// registry.DeriveKey uses, a different domain separator), hashes it with SHA-256,
// and returns the first 16 lowercase-hex characters. The length-prefixing makes
// the suffix escape-proof: no crafted handle can forge another owner's Tenant or
// Caller bytes, because a length prefix can never be parsed as content, so two
// distinct (owner, handle) triples never share a pre-image. It is DETERMINISTIC
// and salt-free: the same (owner, handle) always derives the same suffix, so a
// chat re-addressing its scope on a later create lands on the same subtree. The
// handle is host-derived here (the caller passes st.handle), never a raw body
// string; the owner is the host-attested Identity (NFR-SEC-43).
func scopeHandle(owner state.Identity, handle string) string {
	h := sha256.New()
	writeScopeField(h, scopeHandleVersion)
	writeScopeField(h, owner.Tenant)
	writeScopeField(h, owner.Caller)
	writeScopeField(h, handle)
	return hex.EncodeToString(h.Sum(nil))[:scopeHandleHexLen]
}

// writeScopeField appends one length-prefixed field to the scope-handle
// pre-image: an 8-byte big-endian length, then the raw bytes. The fixed-width
// prefix means a value containing any delimiter byte cannot be parsed as a field
// boundary, so no input can straddle two logical fields.
func writeScopeField(h hash.Hash, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	// A hash.Hash Write never returns an error; both writes are unconditional.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}
