// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package mcpkeyset is the config-plane artifact writer for the MCP API key
// surface, the direct analogue of internal/jwks for the JWKS artifact.
//
// # Responsibility
//
// This package writes two artifacts:
//
//   - WriteKeySet: the Control→gateway boot-set — a versioned in-process
//     envelope carrying only the ACTIVE, non-expired records (revoked and
//     expired records are OMITTED — fail-closed). Written atomically via
//     temp+fsync+rename (POSIX-atomic rename) so a reader sees the old complete
//     artifact or the new, never a half-written set. Mode 0644 — this is NOT
//     secret material; it is a boot-set index analogous to the JWKS public keys.
//     The published FIELD SET is A2-FENCED to the architect's canon wire-freeze
//     (Q4/Q7 from 08-RESEARCH.md); the writer renders a versioned in-process
//     shape and 08-05 maps it to the frozen canon field list at the wire-freeze
//     checkpoint. Do NOT treat the current in-process shape as a frozen contract.
//
//   - WriteEntriesFile / LoadEntriesFile: the minimal-shelf hashed-entries file
//     — a SINGLE versioned JSON object {"version":1,"records":[…]} holding the
//     FULL at-rest records (key_hash + salt, NEVER the plaintext secret). Written
//     0600 root-owned (the house pattern from internal/handoff and
//     internal/provisioning — these are HASHES of secrets, not public keys).
//     LoadEntriesFile fails closed on a file with looser-than-0600 permissions
//     (a store-disclosure surface) and on a truncated/garbled document.
//
// # No network surface
//
// This package adds NO network surface. It performs disk syscalls only (os.CreateTemp,
// Write, Sync, Close, os.Rename). It opens no listener and serves nothing — the
// deploy layer (or the daemon at boot) reads the written file, not this package.
// The two-listener invariant (NFR-SEC-52) is untouched.
//
// # Atomic write pattern
//
// The atomic write follows the house pattern from internal/jwks/artifact.go:
// write to a temp file in the SAME directory, fsync the bytes, then rename over
// the destination. A rename within a directory is atomic on POSIX. A fault in any
// step leaves the OLD complete artifact at the destination; the temp file is cleaned
// up by a deferred os.Remove regardless of the outcome.
package mcpkeyset
