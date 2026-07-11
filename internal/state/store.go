// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package state defines the state.Store seam: the single persistence contract
// the control plane welds its session registry, deny posture, and quota
// counters to. Control logic depends on this interface only — never on a
// concrete database type. An in-memory implementation ships on the minimal
// shelf; a Postgres implementation (internal/state/postgres) sits behind the same
// interface for cross-restart durability. Both pass one shared conformance suite.
//
// Each method below traces to a numbered Phase-1 requirement; no requirement is
// left without a method, and no method exists that a requirement does not force.
//
//   - CREATE is row-as-reservation: Reserve writes a durable reservation row
//     under a per-key advisory lock before any side effect, and a refused create
//     leaves no row (the no-orphan-state property — requirement 2).
//   - Reserve / Commit / Release / BindContainerName are serialized per
//     reservation key by an advisory lock the Store owns, so concurrent callers
//     never double-book a row or leak an orphan (requirement 2).
//   - The deny posture (a global kill-switch plus per-session denylist entries)
//     is durable and scope-tagged, so a restart can reload it and re-engage
//     DENY-ALL before any listener binds (requirements 3, 4).
//   - Quota counters expose an atomic check-and-increment so admission cannot
//     race a TOCTOU window between the read and the increment (requirement 7).
//   - The host-derived identity is the authority on every mutation; a
//     request-supplied id is data on the row, never the thing a method trusts
//     (requirement 5, NFR-SEC-43).
//   - Time enters through an injected Clock; window math uses caller-computed
//     opaque labels, so no TTL or revocation comparison subtracts a persisted
//     timestamp and no wall-clock setback moves a window (requirement 6).
//
// Atomicity is a per-method guarantee, not a caller-orchestrated unit of work:
// there is no transaction handle on this interface because no Phase-1 flow spans
// two methods atomically. The four reservation mutators (Reserve, Commit,
// Release, BindContainerName) each run their whole body inside one held advisory
// lock for the key, with commit-on-nil and rollback-on-error/panic/ctx-cancel
// semantics; no mutator may touch a reservation row outside that held lock.
package state

import (
	"context"
	"errors"
	"time"
)

// Clock is the time seam. The Store and everything above it read time through
// this interface so later-phase TTL and revocation windows run against a
// monotonic source; a wall-clock setback must neither extend a token nor defer a
// revoke (requirement 6, NFR-SEC-48). The Store does no time math itself: it
// stamps a row with Now and never subtracts a persisted timestamp. Duration
// comparisons that drive a security decision measure Since between two in-process
// readings — never a value loaded back from durable storage, whose monotonic
// reading is lost across the round-trip.
type Clock interface {
	// Now returns the current instant for stamping a row.
	Now() time.Time
	// Since returns the monotonic elapsed time from a mark Now produced in this
	// process. It is immune to wall-clock setbacks and is the only time source a
	// TTL or revocation comparison may use. It must not be passed a timestamp
	// read back from durable storage.
	Since(mark time.Time) time.Duration
}

// SessionState is the lifecycle position of a reservation row. The set is
// closed: a row is created RESERVED, advances to ACTIVE on Commit, and reaches
// RELEASED on Release. There is no path back, and RELEASED is a tombstone, not a
// delete — a released row stays visible (distinct from never-reserved) so the
// no-orphan accounting and later-phase audit correlation have a terminal record.
// A Commit or Release against a row already past the required state is a typed
// conflict, not a silent overwrite (requirement 2 — no double-book).
type SessionState uint8

const (
	// StateReserved is a row written by Reserve before any side effect runs.
	StateReserved SessionState = iota
	// StateActive is a reservation Commit promoted after its side effects
	// (network, container) succeeded.
	StateActive
	// StateReleased is the terminal tombstone whose capacity has been returned.
	StateReleased
)

// Identity is the host-derived caller identity: the runtime-attested principal
// the host resolved, never a body-supplied hint. Every authority decision keys
// on this value; a request-carried session / tenant / container_name id travels
// as data on the row, never as the thing methods trust (requirement 5 —
// authority/hint split, NFR-SEC-43). Tenant scopes the per-tenant quota
// dimensions; Caller scopes the per-caller create-rate.
type Identity struct {
	// Tenant is the host-resolved tenant the session is billed and quota'd
	// against. It is the quota scope for the per-tenant dimensions.
	Tenant string
	// Caller is the host-resolved principal that issued the request. It is the
	// quota scope for the per-caller create-rate dimension.
	Caller string
}

// DenyScope distinguishes the two durable deny postures so a reload can
// re-engage each at the right breadth (requirement 4 — deny-durability split by
// scope). The two are stored distinctly and survive a restart in the Postgres
// implementation.
type DenyScope uint8

const (
	// ScopeGlobal is the deployment-wide kill-switch: when engaged every create
	// is refused regardless of session or tenant (DENY-ALL).
	ScopeGlobal DenyScope = iota
	// ScopeSession is a single denylisted reservation key: only a create that
	// resolves to that key is refused.
	ScopeSession
)

// DenyEntry is one durable deny record. A reload reads the full set and
// re-engages the posture before any listener binds (requirement 3). For
// ScopeGlobal the Key is empty; for ScopeSession the Key is the denylisted
// reservation key. Reason and Since are operator-facing context for the audit
// trail, not part of the match decision.
type DenyEntry struct {
	Scope  DenyScope
	Key    string
	Reason string
	Since  time.Time
}

// SessionRow is the persisted reservation record. Key is host-derived and is the
// advisory-lock subject and the row's primary key. Owner is the host-derived
// authority. ContainerName is the runtime container identity bound once after
// Commit by BindContainerName — empty until then; it is recorded data, never the
// authority for any decision (requirement 5).
type SessionRow struct {
	// Key is the host-derived reservation key: the advisory-lock subject and the
	// row identity. Every reservation mutator addresses a row by it.
	Key string
	// Owner is the host-derived identity that holds the reservation. Every
	// mutator verifies the caller's Identity matches before mutating the row.
	Owner Identity
	// State is the lifecycle position (RESERVED → ACTIVE → RELEASED).
	State SessionState
	// ContainerName is the runtime container identity, bound once after Commit.
	// It is empty until BindContainerName succeeds. It is recorded data and is
	// never consulted as authority.
	ContainerName string
}

// Caps mirrors the hard resource caps the provider stamps onto a runtime, as
// recorded data on the durable row for the admin read-surface. It is a
// state-local type by design: internal/state imports neither internal/runtime
// nor any provider, so the durable layer carries no dependency on the runtime
// seam. The lifecycle bridge (internal/runtimemap) is the single named place a
// runtime.ResourceCaps is relabelled into this, guarded by a field-parity test,
// exactly as the Identity bridge is. These are caps (hard ceilings), never
// shares, and are recorded data only — no authority is keyed on them.
type Caps struct {
	// CPUCores is the hard CPU ceiling in fractional cores.
	CPUCores float64
	// MemoryBytes is the hard memory ceiling.
	MemoryBytes int64
	// PidsLimit caps the process count. A nil value means "unset" (no recorded
	// pids cap), preserving the runtime seam's nil-means-unset convention.
	PidsLimit *int64
}

// EnrichedSessionRow is the read-surface view of a reservation row: the frozen
// SessionRow plus the durable read-only enrichment the admin read-API exposes —
// the reservation instant, the RESERVED -> ACTIVE transition instant (nil until
// the row is activated), and the resource caps recorded at activation (nil until
// then). It is returned ONLY by the optional EnrichedLister seam and never by a
// frozen Store mutator; the frozen SessionRow is embedded unchanged, so the
// Phase-1 core is not widened. Every enrichment field is recorded data — no
// authority is keyed on any of it (NFR-SEC-43).
type EnrichedSessionRow struct {
	// SessionRow is the frozen core row, byte-identical to what the mutators
	// return.
	SessionRow
	// ReservedAt is the instant Reserve wrote the row.
	ReservedAt time.Time
	// ActiveAt is the instant the row transitioned RESERVED -> ACTIVE, recorded
	// out of band of the frozen Commit by RecordActivation. It is nil for a row
	// that has not been activated (still RESERVED, or never reached ACTIVE).
	ActiveAt *time.Time
	// Caps are the hard resource caps recorded at activation. They are nil until
	// RecordActivation runs (a still-RESERVED row, or a pre-enrichment row).
	Caps *Caps
	// LastActivity is the Clock instant of the row's most recent activity (its
	// activation, then every exec/control-RPC touch). It is nil for a row with no
	// recorded activity (still RESERVED). The idle-reaper reads it to measure the
	// idle window as Clock.Now() minus this stamp — two in-process Clock readings,
	// never a persisted-timestamp subtraction (NFR-SEC-48).
	LastActivity *time.Time
	// EffectiveScope is the per-chat storage scope derived at create when the
	// deployment runs -derive-chat-scope (ADR-0030): "<base>-<hex>". It is nil until
	// RecordEffectiveScope runs (derivation off, a no-scope create, or a
	// pre-enrichment row). It is recorded read-surface data the caller-scoped status
	// verb surfaces so a chat can confirm its isolated subtree; no authority is keyed
	// on it (NFR-SEC-43) - the guest's minted Storage-JWT claim is the load-bearing
	// isolation, not this label.
	EffectiveScope *string
}

// QuotaDim names a counter dimension. The Store holds the counters; the policy
// (the limit and the decision) lives above in the admission gate. The set is the
// four Phase-3 per-tenant dimensions plus the per-caller create-rate
// (requirement 7 — quota counters without a TOCTOU race).
type QuotaDim uint8

const (
	// DimConcurrentSessions counts live (RESERVED+ACTIVE) sessions per tenant.
	DimConcurrentSessions QuotaDim = iota
	// DimMCPCallsPerMin counts MCP calls per tenant within a one-minute window.
	DimMCPCallsPerMin
	// DimStorageGB counts provisioned storage gigabytes per tenant.
	DimStorageGB
	// DimEgressBytesPerDay counts egress bytes per tenant within a one-day window.
	DimEgressBytesPerDay
	// DimCallerCreateRate counts create attempts per caller within a window.
	DimCallerCreateRate
)

// QuotaKey addresses one counter cell: a dimension, the identity it bills, and a
// window label. DimCallerCreateRate bills Identity.Caller; every other dimension
// bills Identity.Tenant — the Store derives the facet from the dimension, so the
// caller passes the whole Identity. Window is a caller-computed opaque bucket
// label (e.g. a truncated-minute or truncated-day string the admission gate
// derived through the Clock); the Store treats it as an opaque key segment and
// does no time math on it. Two cells with different Window labels are distinct
// counters, so a new window starts a fresh count without the Store subtracting a
// persisted timestamp (requirement 6). For the level dimensions
// (DimConcurrentSessions, DimStorageGB) the caller passes an empty Window.
type QuotaKey struct {
	Dim      QuotaDim
	Identity Identity
	Window   string
}

// Sentinel errors. Callers match with errors.Is; implementations wrap with %w
// and never return a bare dynamic error for these conditions, so admission, the
// kill-switch gate, and the boot sequencer can branch on a stable typed value
// (repo convention: sentinel + %w).
var (
	// ErrStoreUnavailable wraps a transient backing-store failure (a dropped
	// connection, a ctx cancel mid-statement). It is fail-closed evidence: the
	// boot sequencer treats it as not-ready and the admission gate treats it as a
	// REFUSAL, never an allow, so a briefly-unreachable store cannot open a hole
	// in the kill-switch-first boot (requirement 3, NFR-SEC-01).
	ErrStoreUnavailable = errors.New("state: backing store unavailable")
	// ErrKillSwitchEngaged is returned by Reserve when the global kill-switch is
	// engaged. The create is refused and no reservation row is written
	// (requirement 3, NFR-SEC-01).
	ErrKillSwitchEngaged = errors.New("state: global kill-switch engaged, create refused")
	// ErrSessionDenied is returned by Reserve when the reservation key matches a
	// per-session denylist entry. No row is written (requirement 4).
	ErrSessionDenied = errors.New("state: session denylisted, create refused")
	// ErrReservationExists is returned by Reserve when the key already holds a
	// live reservation. The existing row is untouched (requirement 2 — no
	// double-book).
	ErrReservationExists = errors.New("state: reservation already exists for key")
	// ErrReservationNotFound is returned by a mutator or LookupSession when no row
	// addresses the key.
	ErrReservationNotFound = errors.New("state: no reservation for key")
	// ErrReservationConflict is returned by a mutator when the row is not in the
	// state the transition requires (e.g. committing a released row), or when the
	// caller's Identity does not own the row (requirement 2; requirement 5).
	ErrReservationConflict = errors.New("state: reservation state conflict")
	// ErrBindingExists is returned by BindContainerName when the row already has a
	// container_name bound (rebind-poison protection) or when the container_name
	// is already bound to another row (two sessions cannot claim one runtime
	// identity). The existing binding is untouched (requirement 1 — write-once
	// bind).
	ErrBindingExists = errors.New("state: container_name already bound")
	// ErrQuotaExceeded is returned by Charge when applying the delta would carry
	// the counter past the supplied limit; the counter is left unchanged
	// (requirement 7 — atomic check-and-increment, no TOCTOU).
	ErrQuotaExceeded = errors.New("state: quota dimension exceeded")
)

// Store is the persistence seam. Every method takes a context.Context first and
// is safe for concurrent use. The reservation mutators (Reserve, Commit, Release,
// BindContainerName) run under a per-key advisory lock the implementation owns;
// the deny methods carry the durable kill-switch and denylist; the quota methods
// hold the counters. The in-memory and Postgres implementations satisfy this
// exact interface and pass one shared conformance suite.
type Store interface {
	// Reserve writes a reservation row for key under the per-key advisory lock,
	// checking the deny posture inside that same critical section in fail-closed
	// order. It refuses — writing no row — when the global kill-switch is engaged
	// (ErrKillSwitchEngaged), then when key is denylisted (ErrSessionDenied), then
	// when key already holds a live reservation (ErrReservationExists). On success
	// the row is durable and in StateReserved before Reserve returns, so it exists
	// before any caller side effect runs (requirements 2, 3, 4). owner is the
	// host-derived authority. A transient store failure returns ErrStoreUnavailable
	// and admission must treat it as a refusal.
	Reserve(ctx context.Context, key string, owner Identity) (SessionRow, error)

	// Commit promotes the caller's reservation from StateReserved to StateActive
	// under the per-key lock, after its side effects succeeded. It returns
	// ErrReservationNotFound if no row addresses key, and ErrReservationConflict
	// if the row is not StateReserved or owner does not match the row's Owner
	// (requirements 2, 5).
	Commit(ctx context.Context, key string, owner Identity) (SessionRow, error)

	// BindContainerName records the runtime container identity on the caller's
	// row once it exists (host-assigned after Commit). It is write-once: it
	// returns ErrBindingExists if the row already has a container_name or if
	// containerName is already bound to another row (no two sessions share one
	// runtime identity, no rebind poison). It returns ErrReservationNotFound for
	// an unknown key and ErrReservationConflict on an owner mismatch. This is the
	// "bind container_name" Store operation requirement 1 names; LookupSession is
	// the matching read.
	BindContainerName(ctx context.Context, key string, owner Identity, containerName string) (SessionRow, error)

	// Release moves the caller's reservation to the StateReleased tombstone under
	// the per-key lock, returning its capacity. It is the single rollback for a
	// refused or torn-down create, so a Reserve that fails downstream calls
	// Release to guarantee no orphan row survives (requirement 2 — no orphan). It
	// is idempotent against an already-released row (returns the terminal row, no
	// error, no double credit); it returns ErrReservationNotFound for an unknown
	// key and ErrReservationConflict on an owner mismatch (requirement 5).
	Release(ctx context.Context, key string, owner Identity) (SessionRow, error)

	// LookupSession reads the current row for key without taking the advisory
	// lock, for the read paths (status, the container_name binding). It returns
	// ErrReservationNotFound when no row exists. The returned ContainerName is
	// recorded data; callers treat it as data, never authority (requirement 5).
	LookupSession(ctx context.Context, key string) (SessionRow, error)

	// SetDeny writes a durable deny entry (global kill-switch or per-session
	// denylist) and engages it immediately. Re-setting an already-set scope/key is
	// idempotent. The Postgres implementation persists it so a restart reload
	// re-engages it (requirement 4).
	SetDeny(ctx context.Context, entry DenyEntry) error

	// ClearDeny removes a durable deny entry by scope and key (empty key for
	// ScopeGlobal), lifting it. Clearing an absent entry is idempotent.
	ClearDeny(ctx context.Context, scope DenyScope, key string) error

	// LoadDeny returns the full durable deny posture. The daemon calls it at boot
	// to re-engage DENY-ALL from durable state before any listener binds, and
	// /healthz reports not-ready until this read has succeeded. A transient store
	// failure returns ErrStoreUnavailable, which the boot sequencer treats as
	// not-ready (requirement 3, NFR-SEC-01).
	LoadDeny(ctx context.Context) ([]DenyEntry, error)

	// Charge atomically reads the counter cell for key, refuses with
	// ErrQuotaExceeded if the current value plus delta would exceed limit (leaving
	// the cell unchanged), and otherwise applies delta and returns the new value.
	// The check and the increment happen in one critical section, so admission
	// cannot race a TOCTOU window — including the first-ever charge into an absent
	// cell, which is guarded against limit exactly as the conflict path is
	// (requirement 7). A negative delta releases previously charged capacity, is
	// never refused, and saturates at zero (the counter never goes negative).
	Charge(ctx context.Context, key QuotaKey, delta, limit int64) (int64, error)

	// ReadQuota returns the current counter value for key without mutating it. It
	// is a snapshot for reporting only and MUST NOT drive an admission decision
	// the caller intends to honor: a Read-then-Charge is a TOCTOU race, so gate
	// only with the atomic Charge (requirement 7).
	ReadQuota(ctx context.Context, key QuotaKey) (int64, error)
}
