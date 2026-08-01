// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package registry is the SOLE custodian of the session reservation registry
// (requirement 4): the only place in the tree that calls the four Store
// reservation mutators (Reserve, Commit, Release, BindContainerName). The
// lifecycle layer and the kill-switch route every registry mutation through the
// Custodian rather than touching the Store mutators directly, so sole-custody is
// one type and one CI-grep target. A grep asserts no package outside this one
// references those four Store methods.
//
// The registry Key is the load-bearing compile fact (NFR-SEC-43): its single
// field is UNEXPORTED and there is NO constructor that takes a raw request
// string. The only way to obtain a Key is DeriveKey(owner, host-minted-handle),
// which mixes the host-resolved caller Identity into a structured, length-prefixed
// pre-image before hashing — so a body-supplied id can never BECOME a Key, and no
// crafted handle can escape the caller's namespace via a delimiter. Two callers
// passing the same handle get different keys; the body session hint only ever
// seeds the human-readable handle the host mints, never the namespace.
//
// Audience-scoping (NFR-SEC-43): LookupForCaller returns ErrNotOwned for a row the
// caller does not own AND for a missing row, deliberately indistinguishable, so a
// forge attempt cannot tell "exists but not yours" from "absent" and cross-tenant
// enumeration cannot probe existence.
//
// The package imports internal/state only.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"time"

	"github.com/Wide-Moat/ocu-control/internal/state"
)

// Key is the host-derived reservation key. Its single field is UNEXPORTED and
// there is NO constructor that takes a raw request string, so a body-supplied id
// can never become a Key — a compile fact, not a function discipline. The only
// producer is DeriveKey. The String method exposes the opaque value for logging
// and audit only; it is never parsed back into a Key.
type Key struct {
	k string
}

// String returns the opaque derived key value for logging and audit correlation
// only. It is one-way: there is no constructor that turns a string back into a
// Key, so a logged value cannot be replayed as authority.
func (k Key) String() string {
	return k.k
}

// IsZero reports whether k is the zero Key (never produced by DeriveKey). The
// lifecycle uses it to assert a derived key is non-empty before any Store call.
func (k Key) IsZero() bool {
	return k.k == ""
}

// keyVersion prefixes the derivation pre-image so a future change to the scheme
// is distinguishable and never collides with a key minted under an earlier
// version.
const keyVersion = "ocu-key-v1"

// DeriveKey produces the host-derived reservation Key from the host-resolved
// caller Identity and a host-minted opaque session handle. The derivation builds
// a length-prefixed pre-image (a version tag, then each of Tenant, Caller, and
// handle as a 64-bit big-endian length followed by its bytes) and hashes it with
// SHA-256, returning the hex digest. The length-prefixing is what makes the
// namespace escape-proof: no crafted handle can forge the bytes of another
// caller's Tenant or Caller field, because a length prefix can never be confused
// for content, so two distinct (owner, handle) triples can never share a
// pre-image. Two callers passing the same handle get DIFFERENT keys (their
// Identity differs), and the body session hint is NOT an input here — it only
// seeds the human-readable handle the host mints upstream.
func DeriveKey(owner state.Identity, handle string) Key {
	h := sha256.New()
	writeField(h, keyVersion)
	writeField(h, owner.Tenant)
	writeField(h, owner.Caller)
	writeField(h, handle)
	return Key{k: hex.EncodeToString(h.Sum(nil))}
}

// writeField appends one length-prefixed field to the hash pre-image: an 8-byte
// big-endian length, then the raw bytes. The fixed-width prefix means a value
// containing any delimiter byte cannot be parsed as a field boundary, so no input
// can straddle two logical fields.
func writeField(h hash.Hash, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	// A hash.Hash Write never returns an error; the prefix and the payload are
	// written unconditionally.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

// ErrNotOwned is the audience-scoping refusal. It is deliberately the SAME
// not-addressable shape a not-found surfaces, so a forge attempt cannot
// DISTINGUISH "exists but not yours" from "absent" (cross-tenant enumeration
// blocked). The gateway-facing layer maps both ErrNotOwned and
// state.ErrReservationNotFound to a single indistinguishable outcome.
var ErrNotOwned = errors.New("registry: session not addressable")

// ErrEnumerationUnsupported is the fail-closed result of ReservedAndActiveKeys
// when the bound Store does not provide the live-session enumeration capability.
// The frozen Phase-1 state.Store interface exposes per-key reads (LookupSession)
// but no list-all, because no Phase-1 flow enumerated rows; RevokeAll's
// force-kill-EVERY-RESERVED+ACTIVE step and the boot reconciler's row sweep are
// the first callers to need it. A Store opts in by implementing LiveLister; until
// it does, ReservedAndActiveKeys returns this sentinel rather than silently
// reporting an EMPTY set, so RevokeAll fails closed (it refuses to claim it
// force-killed every row when it could not even enumerate them) instead of
// leaving a just-reserved session live. This is the registry's seam for the
// live-enumeration capability both shipped Stores provide via LiveSessions; it
// touches the frozen Store interface not at all.
var ErrEnumerationUnsupported = errors.New("registry: store does not support live-session enumeration")

// LiveLister is the narrow optional capability a Store may implement to enumerate
// its live (RESERVED+ACTIVE) reservation rows. It is deliberately SEPARATE from
// state.Store: the frozen Phase-1 interface is not widened here, and a Store that
// does not enumerate is simply not asserted to satisfy this. The Custodian type-
// asserts its Store to LiveLister inside ReservedAndActiveKeys, so the moment the
// durable Store grows the method the force-kill-every and reconciler sweeps light
// up with no change above this package.
type LiveLister interface {
	// LiveSessions returns every reservation row currently in StateReserved or
	// StateActive. It is a snapshot read (no advisory lock) for the kill-switch
	// force-kill-every step and the boot reconciler; a transient store failure
	// returns state.ErrStoreUnavailable.
	LiveSessions(ctx context.Context) ([]state.SessionRow, error)
}

// EnrichedLister is the optional read capability the admin read-API consumes: it
// enumerates the live reservation rows WITH the durable read-surface enrichment
// (reserved-at, active-at, caps) the dashboard renders. It is SEPARATE from both
// state.Store and LiveLister for the same reason LiveLister is separate — the
// frozen Phase-1 interface is not widened, and a Store that does not enrich is
// simply not asserted to satisfy this. Both shipped Stores implement it; the
// read-API type-asserts its Store to EnrichedLister and fails closed
// (ErrEnumerationUnsupported) if a Store does not, never reporting an empty set.
// Like LiveSessions it is a snapshot read (no advisory lock): the admin surface
// is read-only and tolerates a row mutating under it.
type EnrichedLister interface {
	// LiveSessionsEnriched returns every reservation row currently in
	// StateReserved or StateActive as an EnrichedSessionRow (the frozen row plus
	// reserved-at, active-at, caps). A transient store failure returns
	// state.ErrStoreUnavailable, fail-closed, exactly as LiveSessions does.
	LiveSessionsEnriched(ctx context.Context) ([]state.EnrichedSessionRow, error)
}

// ActivationRecorder is the optional write capability that records the
// read-surface enrichment at the RESERVED -> ACTIVE transition. It is called by
// the lifecycle activation IMMEDIATELY AFTER the frozen Commit (never inside it):
// Commit's signature stays byte-identical, and the enrichment is persisted out of
// band of the state flip. The admin read-surface is read-only and tolerates the
// millisecond eventual-consistency window between the state flip and this record
// — a read sees either the pre-record (no caps/active-at) or post-record (with)
// view, both valid — so no atomicity invariant is owed (ADR-0022). A transient
// store failure returns state.ErrStoreUnavailable; the caller treats a record
// failure as non-fatal to the create (the row is already ACTIVE and correct; only
// the read-surface enrichment is missing), and MUST NOT unwind the commit on it.
type ActivationRecorder interface {
	// RecordActivation stamps the activation instant and the recorded caps onto
	// an already-committed (ACTIVE) row, keyed on the host-derived reservation
	// key. It is idempotent: re-recording the same key overwrites with the same
	// data. A transient store failure returns state.ErrStoreUnavailable.
	RecordActivation(ctx context.Context, key string, caps state.Caps, at time.Time) error
}

// EffectiveScopeRecorder is the optional write capability that records the
// per-chat effective storage scope onto an already-committed row (ADR-0030, D5).
// It mirrors ActivationRecorder: the lifecycle commit stage calls it out of band
// IMMEDIATELY AFTER the frozen Commit (never inside it), keyed on the host-derived
// key, so the frozen Commit signature is unchanged and the scope is persisted out
// of band of the state flip. It is NON-FATAL to the create: the scope was already
// minted into the guest's Storage-JWT before the commit, so a record failure only
// leaves the read-surface enrichment absent until re-recorded (recovery is a
// re-derivation from the persisted owner+handle, not a stored secret). A Store
// without the capability yields ErrEnumerationUnsupported, which the caller treats
// the same non-fatal way. A transient store failure returns state.ErrStoreUnavailable.
type EffectiveScopeRecorder interface {
	// RecordEffectiveScope stamps the per-chat effective storage scope onto an
	// already-committed (ACTIVE) row, keyed on the host-derived reservation key. It
	// is idempotent: re-recording the same key overwrites with the same data. A
	// transient store failure returns state.ErrStoreUnavailable.
	RecordEffectiveScope(ctx context.Context, key string, scope string) error
}

// Custodian is the SOLE writer of the session registry (requirement 4): the only
// type in the tree that calls state.Store.{Reserve,Commit,Release,
// BindContainerName}. The lifecycle Manager and the kill-switch Engine call these
// wrappers, never the Store mutators directly; a CI import-graph grep asserts no
// other package references those four Store methods. Every method keys on the
// host-derived owner Identity, never a body field, and addresses a row by the
// opaque derived Key.
type Custodian struct {
	store state.Store
}

// NewCustodian constructs a Custodian bound to the Store. It is the single
// authorized holder of the four reservation mutators.
func NewCustodian(store state.Store) *Custodian {
	return &Custodian{store: store}
}

// Reserve writes the first durable reservation row for key under the Store's
// per-key advisory lock, re-checking the deny posture inside that critical
// section (so a revoke landing mid-create still refuses here). owner is the
// host-derived authority. It returns the Store's typed errors unchanged
// (ErrKillSwitchEngaged, ErrSessionDenied, ErrReservationExists,
// ErrStoreUnavailable) for the caller to branch on.
func (c *Custodian) Reserve(ctx context.Context, key Key, owner state.Identity) (state.SessionRow, error) {
	return c.store.Reserve(ctx, key.k, owner)
}

// Commit promotes the caller's reservation from RESERVED to ACTIVE under the
// per-key lock. It returns ErrReservationNotFound for an unknown key and
// ErrReservationConflict on a state mismatch or owner mismatch.
func (c *Custodian) Commit(ctx context.Context, key Key, owner state.Identity) (state.SessionRow, error) {
	return c.store.Commit(ctx, key.k, owner)
}

// BindContainerName records the runtime container identity on the caller's row
// once it exists (host-assigned after Commit), write-once. It returns
// ErrBindingExists if the row already has a container name or the name is bound
// elsewhere, ErrReservationNotFound for an unknown key, and ErrReservationConflict
// on an owner mismatch.
func (c *Custodian) BindContainerName(ctx context.Context, key Key, owner state.Identity, containerName string) (state.SessionRow, error) {
	return c.store.BindContainerName(ctx, key.k, owner, containerName)
}

// Release moves the caller's reservation to the RELEASED tombstone under the
// per-key lock, returning its capacity. It is the single rollback for a refused
// or torn-down create and is idempotent against an already-released row. It
// returns ErrReservationNotFound for an unknown key and ErrReservationConflict on
// an owner mismatch.
func (c *Custodian) Release(ctx context.Context, key Key, owner state.Identity) (state.SessionRow, error) {
	return c.store.Release(ctx, key.k, owner)
}

// ReleaseRow releases a row the Custodian itself enumerated via
// ReservedAndActiveKeys, addressing it by the row's own opaque Store key and
// host-derived owner. It exists because an enumerated row carries a raw key string,
// not a derived Key, and registry.Key has no raw-string constructor — so the boot
// reconciler cannot rebuild a Key to release a reclaimed RESERVED row. It is NOT
// audience-scoped (only the boot reconciler and the operator-scoped kill-switch
// enumerate rows and call it), and it keeps sole-custody intact: the Store.Release
// call still lives inside this one type. Release is idempotent against an
// already-released row, so a re-run never double-credits. It returns the Store's
// typed errors unchanged.
func (c *Custodian) ReleaseRow(ctx context.Context, row state.SessionRow) (state.SessionRow, error) {
	return c.store.Release(ctx, row.Key, row.Owner)
}

// ForceReleaseRow releases a row the kill-switch enumerated for a force-kill,
// addressing it by the row's own opaque key and host-derived owner exactly as
// ReleaseRow does. It is the registry seam the operator-scoped kill-switch uses to
// drive a force-killed RESERVED+ACTIVE row to the RELEASED tombstone after the
// provider finalizer reclaims the substrate; folding it onto the Custodian keeps the
// four Store mutators custodied in one type. It is idempotent and returns the
// Store's typed errors unchanged.
func (c *Custodian) ForceReleaseRow(ctx context.Context, row state.SessionRow) (state.SessionRow, error) {
	return c.store.Release(ctx, row.Key, row.Owner)
}

// LookupForCaller returns the row addressed by key ONLY if owner matches the
// row's Owner. On any owner mismatch — or a missing row — it returns ErrNotOwned
// and discloses nothing about the row (NFR-SEC-43), so "exists but not yours" is
// indistinguishable from "absent" and enumeration cannot probe existence. The
// body-supplied id is a HINT used only to ADDRESS the row through the derived
// key; owner is the host-derived authority the row is gated on. A transient store
// failure (ErrStoreUnavailable) propagates unchanged.
func (c *Custodian) LookupForCaller(ctx context.Context, key Key, owner state.Identity) (state.SessionRow, error) {
	row, err := c.store.LookupSession(ctx, key.k)
	if err != nil {
		if errors.Is(err, state.ErrReservationNotFound) {
			// Collapse not-found into the same not-addressable refusal so a missing
			// row is indistinguishable from a foreign-owned one.
			return state.SessionRow{}, ErrNotOwned
		}
		return state.SessionRow{}, err
	}
	if row.Owner != owner {
		// A foreign-owned row discloses nothing: same refusal as not-found.
		return state.SessionRow{}, ErrNotOwned
	}
	return row, nil
}

// ReservedAndActiveKeys enumerates the live (RESERVED+ACTIVE) rows for the boot
// reconciler→quota coupling and for RevokeAll's force-kill-every-row step, which
// MUST include RESERVED rows (a just-reserved-not-yet-committed session), not only
// ACTIVE ones. It is NOT audience-scoped: only the operator-scoped kill-switch and
// the boot reconciler call it.
//
// Enumeration is an OPTIONAL Store capability (LiveLister): the frozen Phase-1
// state.Store has per-key reads but no list-all. The Custodian type-asserts its
// Store; a Store that does not enumerate yields ErrEnumerationUnsupported, which
// is fail-closed — RevokeAll must surface it rather than treat an empty slice as
// "no live rows" and leave a just-reserved session alive. A transient store
// failure propagates unchanged.
func (c *Custodian) ReservedAndActiveKeys(ctx context.Context) ([]state.SessionRow, error) {
	lister, ok := c.store.(LiveLister)
	if !ok {
		return nil, ErrEnumerationUnsupported
	}
	rows, err := lister.LiveSessions(ctx)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// EnrichedLiveSessions is the admin read-API's enumeration through the sole
// custodian: it routes the enriched live-row read via the Store's optional
// EnrichedLister, the same type-assert discipline as ReservedAndActiveKeys. A
// Store that does not enrich yields ErrEnumerationUnsupported (fail-closed — the
// read-API surfaces it rather than reporting an empty set); a transient store
// failure propagates unchanged. The returned rows are recorded data the read
// surface renders; no authority is keyed on them (NFR-SEC-43).
func (c *Custodian) EnrichedLiveSessions(ctx context.Context) ([]state.EnrichedSessionRow, error) {
	lister, ok := c.store.(EnrichedLister)
	if !ok {
		return nil, ErrEnumerationUnsupported
	}
	rows, err := lister.LiveSessionsEnriched(ctx)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// RecordActivation routes the out-of-band activation record through the sole
// custodian, keyed on the registry Key (so the host-derived authority/hint
// boundary is preserved — a raw request string can never reach this). It is
// called by the lifecycle immediately AFTER Commit and is NON-FATAL to the
// create: the row is already ACTIVE and correct; only the read-surface enrichment
// is being persisted, so a transient failure is the caller's to log-and-continue,
// never to unwind the commit on (ADR-0022). A Store without the optional
// ActivationRecorder yields ErrEnumerationUnsupported, which the caller treats the
// same non-fatal way — the read surface simply lacks the enrichment for that row.
func (c *Custodian) RecordActivation(ctx context.Context, key Key, caps state.Caps, at time.Time) error {
	recorder, ok := c.store.(ActivationRecorder)
	if !ok {
		return ErrEnumerationUnsupported
	}
	return recorder.RecordActivation(ctx, key.k, caps, at)
}

// RecordEffectiveScope routes the per-chat effective-scope record through the sole
// custodian, keyed on the registry Key (host-derived; a raw request string can
// never reach this). It is called by the lifecycle commit stage immediately AFTER
// Commit and is NON-FATAL to the create (ADR-0030): the scope was already minted
// into the guest's Storage-JWT before this write, so a record failure only leaves
// the read surface lacking the scope for that row until re-recorded. A Store
// without the optional EffectiveScopeRecorder yields ErrEnumerationUnsupported,
// which the caller treats the same non-fatal way.
func (c *Custodian) RecordEffectiveScope(ctx context.Context, key Key, scope string) error {
	recorder, ok := c.store.(EffectiveScopeRecorder)
	if !ok {
		return ErrEnumerationUnsupported
	}
	return recorder.RecordEffectiveScope(ctx, key.k, scope)
}

// LookupForCallerEnriched returns the caller's OWN enriched row addressed by key,
// the read-surface complement of LookupForCaller (ADR-0030, D5). It exists because
// the frozen LookupForCaller returns the FROZEN state.SessionRow, which carries no
// read-surface enrichment (active-at, caps, effective-scope); the caller-scoped
// status verb needs the EnrichedSessionRow to surface effective_scope without
// widening the frozen core. It type-asserts the optional EnrichedLister seam (the
// same discipline EnrichedLiveSessions uses), enumerates the live enriched rows,
// and returns the one whose Key matches AND whose Owner matches the caller. It
// applies the SAME audience scoping as LookupForCaller: a foreign-owned row, an
// absent row, or a row not in the live (RESERVED+ACTIVE) set all collapse to
// ErrNotOwned, so "exists but not yours" is indistinguishable from "absent" and a
// caller can neither read another tenant's scope nor probe existence (NFR-SEC-43).
// A Store that does not enrich yields ErrEnumerationUnsupported (fail-closed); a
// transient store failure propagates unchanged.
func (c *Custodian) LookupForCallerEnriched(ctx context.Context, key Key, owner state.Identity) (state.EnrichedSessionRow, error) {
	lister, ok := c.store.(EnrichedLister)
	if !ok {
		return state.EnrichedSessionRow{}, ErrEnumerationUnsupported
	}
	rows, err := lister.LiveSessionsEnriched(ctx)
	if err != nil {
		return state.EnrichedSessionRow{}, err
	}
	for i := range rows {
		if rows[i].Key != key.k {
			continue
		}
		if rows[i].Owner != owner {
			// A foreign-owned row discloses nothing: same refusal as not-found.
			return state.EnrichedSessionRow{}, ErrNotOwned
		}
		return rows[i], nil
	}
	// Absent from the live set (never reserved, or already released): collapse to the
	// same not-addressable refusal a foreign row gets.
	return state.EnrichedSessionRow{}, ErrNotOwned
}

// ActivityToucher is the optional write capability that advances a row's
// last-activity stamp. The lifecycle exec path calls it after a successful dispatch
// so the idle-reaper measures idleness from the LAST activity, not from creation. It
// takes now (Clock.Now()) from the caller so the store does no time math — the idle
// window is Clock.Now() minus this stamp, two in-process Clock readings, never a
// persisted-timestamp subtraction (NFR-SEC-48). A Store without it yields
// ErrEnumerationUnsupported; the caller treats a touch failure as non-fatal (the exec
// already succeeded; the row simply keeps its prior stamp and may be reaped a tick
// early — never a create/exec failure).
type ActivityToucher interface {
	TouchActivity(ctx context.Context, key string, now time.Time) error
}

// TouchActivity routes the last-activity advance through the sole custodian, keyed on
// the registry Key (host-derived, never a raw request string). It is NON-FATAL: a
// Store without the optional ActivityToucher yields ErrEnumerationUnsupported, which
// the caller swallows — the reaper falls back to the activation stamp and may reap a
// still-busy session one idle window late at worst, never a data-safety issue.
func (c *Custodian) TouchActivity(ctx context.Context, key Key, now time.Time) error {
	toucher, ok := c.store.(ActivityToucher)
	if !ok {
		return ErrEnumerationUnsupported
	}
	return toucher.TouchActivity(ctx, key.k, now)
}
