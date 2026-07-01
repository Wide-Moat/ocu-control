// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkeyset

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/mcpkey"
)

// ErrEmptyKeySet is the fail-closed refusal WriteKeySet returns when the active,
// non-expired subset of the supplied records is empty. An empty boot-set would
// cause the gateway to reject every presented key (fail-open on the validation
// side) and would mask a misconfiguration. The artifact is never written when
// there are no active records to publish.
var ErrEmptyKeySet = errors.New("mcpkeyset: refusing to write an empty active key set")

// ErrLoosePermissions is returned by LoadEntriesFile when the hashed-entries
// file exists with permissions looser than 0600. A world- or group-readable
// file is a store-disclosure surface (even though it holds only hashes, not
// plaintext secrets), and the load is refused to enforce the root-owned 0600
// posture.
var ErrLoosePermissions = errors.New("mcpkeyset: hashed-entries file has permissions looser than 0600")

// keySetPerm is the mode written for the Control→gateway boot-set artifact.
// It is 0644 (world-readable), NOT the 0600 the hashed-entries file carries.
// The boot-set content is NOT the plaintext secret — it is a hash + salt index
// analogous to the JWKS public key set, and the deploy layer (or the gateway at
// boot) must be able to read it. The temp+fsync+rename write keeps the write
// atomic regardless of the wider mode.
const keySetPerm = 0o644

// entriesPerm is the mode written for the minimal-shelf hashed-entries file.
// 0600 root-owned — these are HASHES of secrets, not public keys. A
// world/group-readable hashed-entries file is a store-disclosure surface.
const entriesPerm = 0o600

// ---- in-process wire shape (A2-FENCED) -------------------------------------
//
// The following types carry the in-process versioned envelope that WriteKeySet
// serializes. The Control→gateway published FIELD SET is A2-FENCED to the
// architect's canon wire-freeze (Q4/Q7, 08-RESEARCH.md). Plan 08-05 maps the
// record fields to the canon-frozen set at the wire-freeze checkpoint.
//
// DO NOT treat these field names as a frozen wire contract. They are an
// in-process shape chosen for correctness of the active-filter + atomic-write
// machinery; the canonical field names come from the architect's wire-freeze.

// keySetRecord is the per-record slice element in the in-process boot-set
// envelope. It carries the fields the gateway needs to recompute sha256(salt‖
// presented) and resolve the binding; revoked/expired records are OMITTED by
// the caller before reaching here.
//
// FIELD SET IS A2-FENCED — the authoritative list comes from canon at the
// wire-freeze checkpoint (08-05). Do not code external consumers against these
// field names.
type keySetRecord struct {
	KeyID      string `json:"key_id"`
	KeyHash    []byte `json:"key_hash"`
	Salt       []byte `json:"salt"`
	Tenant     string `json:"tenant"`
	Deployment string `json:"deployment"`
}

// keySetDoc is the versioned in-process boot-set envelope written by WriteKeySet.
// Version 1 is the only defined version; a format migration will bump this.
//
// FIELD SET IS A2-FENCED — see keySetRecord note above.
type keySetDoc struct {
	Version int            `json:"version"`
	Records []keySetRecord `json:"records"`
}

// entriesDoc is the versioned on-disk envelope for the minimal-shelf
// hashed-entries file. It holds the FULL at-rest record set (both active and
// revoked), written 0600, and is NOT the same artifact as the boot-set.
type entriesDoc struct {
	Version int              `json:"version"`
	Records []mcpkey.Record  `json:"records"`
}

// ---- WriteKeySet ------------------------------------------------------------

// WriteKeySet renders the active, non-expired subset of records as a versioned
// in-process boot-set envelope and writes it ATOMICALLY to path (temp+fsync+
// rename, mirroring jwks.WriteArtifact). Revoked and expired records are OMITTED
// — fail-closed — so a revoked key cannot survive in the published boot-set.
//
// It is fail-closed on an empty active subset (ErrEmptyKeySet): the artifact is
// never written when there is nothing to publish, so the gateway cannot end up
// with a boot-set that accepts no key.
//
// WriteKeySet adds NO network surface: it performs disk syscalls only.
// The deploy layer or the gateway boot-loader reads the file; this package never
// serves it over a listener (NFR-SEC-52, two-listener invariant untouched).
//
// The published FIELD SET is A2-FENCED (see package doc). Plan 08-05 maps the
// in-process keySetRecord fields to the canon-frozen field list at the wire-freeze
// checkpoint. Do not treat the current field names as a frozen gateway contract.
func WriteKeySet(path string, records []mcpkey.Record, now time.Time) error {
	// Filter to the active, non-expired subset FIRST — before any filesystem
	// touch. Revoked or expired records are OMITTED (fail-closed).
	active := make([]keySetRecord, 0, len(records))
	for _, r := range records {
		if !r.IsActive(now) {
			continue
		}
		active = append(active, keySetRecord{
			KeyID:      r.KeyID,
			KeyHash:    r.KeyHash,
			Salt:       r.Salt,
			Tenant:     r.Tenant,
			Deployment: r.Deployment,
		})
	}

	// Fail-closed BEFORE any filesystem touch: an empty active subset is never
	// written as an empty boot-set doc (it would make the gateway reject every
	// presented key, masking a misconfiguration).
	if len(active) == 0 {
		return ErrEmptyKeySet
	}

	doc := keySetDoc{
		Version: 1,
		Records: active,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keyset: %w", err)
	}
	data = append(data, '\n')
	return writeAtomicWithPerm(path, data, keySetPerm)
}

// ---- WriteEntriesFile / LoadEntriesFile -------------------------------------

// WriteEntriesFile writes the FULL at-rest record set to path as a SINGLE
// versioned JSON object {"version":1,"records":[…]}. It holds ALL records
// (both active and revoked) — the minimal-shelf dual to the RecordStore. The
// file is written at mode 0600 (root-owned house pattern), atomically via
// temp+fsync+rename. The plaintext secret is NEVER written: each Record holds
// only key_hash + salt, never the raw sk-ocu- key.
//
// WriteEntriesFile is a full atomic rewrite on every mutation — no in-place
// edit, no append. A crash mid-write leaves either the old complete set or the
// new complete set, never a torn one (POSIX-atomic rename within the directory).
func WriteEntriesFile(path string, records []mcpkey.Record) error {
	if records == nil {
		records = []mcpkey.Record{} // serialize as [] not null
	}
	doc := entriesDoc{
		Version: 1,
		Records: records,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal entries: %w", err)
	}
	data = append(data, '\n')
	return writeAtomicWithPerm(path, data, entriesPerm)
}

// LoadEntriesFile reads the minimal-shelf hashed-entries file at path and
// returns the full at-rest record set. It fails CLOSED on:
//
//   - a file with permissions looser than 0600 (ErrLoosePermissions) — a world-
//     or group-readable hashed-entries file is a store-disclosure surface;
//   - a truncated or garbled JSON document — a parse error, never a silent
//     partial set.
func LoadEntriesFile(path string) ([]mcpkey.Record, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat entries file: %w", err)
	}
	// Fail closed on a looser-than-0600 file: a world- or group-readable
	// hashed-entries file is a store-disclosure surface (NFR-SEC-10 posture).
	if info.Mode().Perm()&0o177 != 0 {
		return nil, ErrLoosePermissions
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read entries file: %w", err)
	}
	var doc entriesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse entries file: %w", err)
	}
	return doc.Records, nil
}

// ---- atomic write infrastructure --------------------------------------------

// tempFile is the narrow os.File surface writeAtomicWithPerm drives. The production
// createTemp returns a real *os.File (which satisfies this); a test overrides
// createTemp to return a fault-injecting fake. Mirrors jwks.tempFile exactly.
type tempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// createTemp is the temp-file constructor writeAtomicWithPerm uses, indirected
// through a package var so a test can inject a fault-injecting fake.
// In production it is the stdlib os.CreateTemp returning a real *os.File.
var createTemp = func(dir, pattern string) (tempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// Compile-time proof that *os.File satisfies the tempFile seam.
var _ tempFile = (*os.File)(nil)

// writeAtomicWithPerm writes data to path atomically at the given mode:
// write to a temp file in the SAME directory → chmod → write → verify length
// → Sync → Close → Rename. A rename within a directory is atomic on POSIX, so
// a reader sees the OLD complete file or the NEW complete file, never a partial
// write. The deferred os.Remove cleans up the temp file on any fault path.
//
// This mirrors internal/jwks/artifact.go#writeAtomic with one parameterisation:
// the mode is a parameter (0644 for the boot-set, 0600 for the entries file).
func writeAtomicWithPerm(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := createTemp(dir, ".tmp-mcpkeyset-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup so a faulted render leaves no stray .tmp-mcpkeyset-*.
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	n, werr := tmp.Write(data)
	if werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", werr)
	}
	if n != len(data) {
		_ = tmp.Close()
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}
