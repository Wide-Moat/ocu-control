// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package mcpkeyset

import (
	"encoding/hex"
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

// ---- published wire shape (A2 — Control→gateway hashed-key-set) -------------
//
// The following types carry the canon-frozen Artifact-2 envelope that
// WriteKeySet serializes: the Control→gateway hashed-key-set contract
// (contracts/mcp/mcp-key-set.schema.json, JSON-Schema-2020-12). The field set
// is FROZEN — it matches the ratified ADR-0027 §Storage record verbatim and is
// the surface the gateway boot-loads to validate a presented sk-ocu- key.
//
// Frozen HashedKeyRecord field set (required: key_id, key_hash, salt, tenant,
// deployment, status, created_at; optional: expires_at):
//   - key_id      string (opaque handle; the --id arg of revoke)
//   - key_hash    lowercase-hex sha256(salt‖secret), 64 hex chars
//   - salt        lowercase-hex per-key salt, ≥16 hex chars (≥64-bit)
//   - tenant      the binding tenant (read from the RECORD, never the key)
//   - deployment  the binding deployment (absent-from-set ⇒ gateway 401)
//   - status      closed enum "active" | "revoked"
//   - expires_at  RFC3339 date-time, OPTIONAL (absent ⇒ non-expiring)
//   - created_at  RFC3339 date-time
//
// FENCED-SURFACE INVARIANT: NO plaintext secret, NO sk-ocu- key, NO unsalted
// digest, NO signing key ever appears here — the artifact is hashes + salts
// only. The schema is additionalProperties:false at both levels, so no extra
// field can smuggle a secret in. The published subset is fail-closed to the
// ACTIVE, non-expired records (revoked/expired are omitted before reaching
// here), so every emitted record carries status "active"; the "revoked" enum
// value exists for schema-generality with the at-rest record, not because a
// revoked key is ever published.

// keySetRecord is the per-record slice element in the published hashed-key-set
// envelope. key_hash and salt are lowercase-hex strings (the byte slices are
// hex-encoded at projection time to satisfy the frozen ^[0-9a-f]+$ patterns);
// the RFC3339 timestamps are formatted from the record's time.Time fields.
type keySetRecord struct {
	KeyID      string `json:"key_id"`
	KeyHash    string `json:"key_hash"`
	Salt       string `json:"salt"`
	Tenant     string `json:"tenant"`
	Deployment string `json:"deployment"`
	Status     string `json:"status"`
	// ExpiresAt is omitted when the record is non-expiring (zero ExpiresAt),
	// matching the frozen "absent ⇒ non-expiring" semantics.
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at"`
}

// keySetDoc is the versioned published hashed-key-set envelope written by
// WriteKeySet. version is the const 1 the frozen schema pins; a format
// migration bumps it. The schema is additionalProperties:false, so this struct
// carries exactly the two frozen top-level fields and nothing else.
type keySetDoc struct {
	Version int            `json:"version"`
	Records []keySetRecord `json:"records"`
}

// entriesDoc is the versioned on-disk envelope for the minimal-shelf
// hashed-entries file. It holds the FULL at-rest record set (both active and
// revoked), written 0600, and is NOT the same artifact as the boot-set.
type entriesDoc struct {
	Version int             `json:"version"`
	Records []mcpkey.Record `json:"records"`
}

// ---- WriteKeySet ------------------------------------------------------------

// WriteKeySet renders the active, non-expired subset of records as the
// canon-frozen Artifact-2 hashed-key-set envelope and writes it ATOMICALLY to
// path (temp+fsync+rename, mirroring jwks.WriteArtifact). Revoked and expired
// records are OMITTED — fail-closed — so a revoked key cannot survive in the
// published boot-set; every emitted record therefore carries status "active".
//
// It is fail-closed on an empty active subset (ErrEmptyKeySet): the artifact is
// never written when there is nothing to publish, so the gateway cannot end up
// with a boot-set that accepts no key.
//
// WriteKeySet adds NO network surface: it performs disk syscalls only.
// The deploy layer or the gateway boot-loader reads the file; this package never
// serves it over a listener (NFR-SEC-52, two-listener invariant untouched).
//
// The published field set is the FROZEN A2 contract (see the keySetRecord doc):
// key_hash and salt are lowercase-hex, timestamps are RFC3339, and no plaintext
// secret is ever projected into the record.
func WriteKeySet(path string, records []mcpkey.Record, now time.Time) error {
	// Filter to the active, non-expired subset FIRST — before any filesystem
	// touch. Revoked or expired records are OMITTED (fail-closed).
	active := make([]keySetRecord, 0, len(records))
	for _, r := range records {
		if !r.IsActive(now) {
			continue
		}
		rec := keySetRecord{
			KeyID:      r.KeyID,
			KeyHash:    hex.EncodeToString(r.KeyHash),
			Salt:       hex.EncodeToString(r.Salt),
			Tenant:     r.Tenant,
			Deployment: r.Deployment,
			// Every published record is active by construction (the IsActive
			// filter above); the field is emitted explicitly because the frozen
			// schema marks status required.
			Status:    string(mcpkey.StatusActive),
			CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
		}
		// expires_at is optional: a zero ExpiresAt is a non-expiring key and the
		// field is omitted entirely (frozen "absent ⇒ non-expiring" semantics).
		if !r.ExpiresAt.IsZero() {
			rec.ExpiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		active = append(active, rec)
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
