// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package state

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
)

// stripeCount is the fixed number of per-key advisory-lock stripes. A
// reservation key hashes (hash64) onto one stripe, so two distinct keys that
// hash to different stripes proceed in parallel while the same key always
// serializes. The Postgres leg keys an advisory lock on the same hash, so the
// in-memory leg models the identical contention surface — distinct-key
// parallelism is real, same-key access is serialized. The count is a power of
// two so the modulo reduces to a mask and stays well above the small set of
// keys a single deployment holds live at once.
const stripeCount = 64

// memStore is the in-memory Store on the minimal shelf: zero external
// dependencies, every guarantee the Store interface names enforced by
// in-process locks. It carries three independent lock domains so the three
// concerns never contend on one mutex:
//
//   - the reservation domain (the striped per-key advisory locks plus the row
//     map and the container_name reverse index, guarded for structural reads
//     and writes by rowMu);
//   - the deny domain (the kill-switch and per-session denylist under denyMu);
//     and
//   - the quota domain (the counter cells under their own striped locks, a
//     distinct domain keyed on the cell hash so a Charge never blocks a Reserve).
//
// All time enters through clk; the store never calls time.Now directly.
type memStore struct {
	clk Clock

	// stripes are the per-key advisory locks. A reservation mutator holds the
	// stripe for hash64(key) for its whole body, so Reserve/Commit/Release/
	// BindContainerName against one key never interleave.
	stripes [stripeCount]sync.Mutex

	// rowMu guards the structural reads and writes of rows and the reverse
	// container_name index. It is held only for the brief map operations, never
	// across a side effect, so it does not serialize distinct keys the way the
	// stripes intentionally serialize one key. A reservation mutator takes its
	// key stripe first, then rowMu for the map touch.
	rowMu sync.Mutex
	// rows is the reservation registry keyed by SessionRow.Key. A RELEASED row
	// stays in the map as a tombstone; it is never deleted.
	rows map[string]SessionRow
	// boundNames is the reverse index from a bound container_name to the
	// reservation key that owns it, enforcing global container_name uniqueness
	// without scanning the row map.
	boundNames map[string]string

	// denyMu guards the deny posture. Reserve reads the posture under it while
	// holding its key stripe, so the deny check and the dependent row insert are
	// one decision for that key. A global SetDeny is not key-scoped and may race
	// an in-flight Reserve; the host-side force-kill path, not this lock, settles
	// that window, and DENY-ALL is engaged at boot before any listener admits a
	// create.
	denyMu sync.RWMutex
	// deny holds the durable deny entries keyed by denyKey(scope, key). The
	// global kill-switch lives at denyKey(ScopeGlobal, "").
	deny map[string]DenyEntry

	// quotaStripes are the per-cell advisory locks for the quota domain — a
	// distinct lock domain from the reservation stripes, keyed on the cell hash,
	// so a Charge serializes only against another Charge to the same cell.
	quotaStripes [stripeCount]sync.Mutex
	// quotaMu guards the structural reads and writes of the counter map. It is
	// taken inside the cell stripe for a Charge and alone for a read-only
	// ReadQuota.
	quotaMu sync.Mutex
	// quota holds the counter cells keyed by QuotaKey. Only the value is stored;
	// Window is an opaque segment of the key and carries no timestamp.
	quota map[QuotaKey]int64
}

// NewInMemory returns the in-memory Store backed by clk. It is safe for
// concurrent use and holds no resource that needs closing.
func NewInMemory(clk Clock) Store {
	return &memStore{
		clk:        clk,
		rows:       make(map[string]SessionRow),
		boundNames: make(map[string]string),
		deny:       make(map[string]DenyEntry),
		quota:      make(map[QuotaKey]int64),
	}
}

// hash64 maps a string onto a stripe index with the FNV-1a 64-bit hash the
// Postgres leg also uses to derive its advisory-lock key, so both legs contend
// on the same partitioning.
func hash64(s string) uint64 {
	h := fnv.New64a()
	// fnv's Write never returns an error; the hash.Hash contract guarantees it.
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// keyStripe returns the per-key advisory lock for a reservation key.
func (m *memStore) keyStripe(key string) *sync.Mutex {
	return &m.stripes[hash64(key)&(stripeCount-1)]
}

// quotaStripe returns the per-cell advisory lock for a quota cell, keyed on the
// dimension and the billed scope id so the lock domain matches the Postgres
// leg's hash(dim, scope_id).
func (m *memStore) quotaStripe(key QuotaKey) *sync.Mutex {
	return &m.quotaStripes[hash64(quotaScopeID(key))&(stripeCount-1)]
}

// quotaScopeID derives the billed scope id for a cell: DimCallerCreateRate bills
// the caller, every other dimension bills the tenant. The window is folded in so
// distinct windows partition onto independent stripes.
//
// The billed identity is length-prefixed so the encoding is unambiguous for any
// content — two cells collide only when their dimension, billed identity, and
// window are all equal, never because a separator happens to appear inside a
// value. The encoding contains no NUL byte: the Postgres leg stores this exact
// string in a text column and hashes it for the advisory lock, and Postgres
// rejects NUL in text (SQLSTATE 22021), so both legs must agree on this same
// NUL-free, length-prefixed form (see internal/state/postgres.quotaScopeID).
func quotaScopeID(key QuotaKey) string {
	billed := key.Identity.Tenant
	if key.Dim == DimCallerCreateRate {
		billed = key.Identity.Caller
	}
	return fmt.Sprintf("%d|%d:%s|%s", key.Dim, len(billed), billed, key.Window)
}

// denyKey is the map key for a deny entry: the scope and, for a session entry,
// the reservation key. The global kill-switch is denyKey(ScopeGlobal, "").
func denyKey(scope DenyScope, key string) string {
	return fmt.Sprintf("%d\x00%s", scope, key)
}

// ctxErr returns a fail-closed ErrStoreUnavailable wrapping ctx.Err when ctx is
// already cancelled at method entry, and nil otherwise. The Store treats a
// cancelled context as a transient backing-store failure so admission refuses
// rather than allows on a torn-down request (NFR-SEC-01).
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}

// Reserve writes a RESERVED row for key under the key stripe, checking the deny
// posture inside that same critical section in fail-closed order: global
// kill-switch, then per-session denylist, then live-row double-book. Any refusal
// writes no row.
func (m *memStore) Reserve(ctx context.Context, key string, owner Identity) (SessionRow, error) {
	if err := ctxErr(ctx); err != nil {
		return SessionRow{}, err
	}

	stripe := m.keyStripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	// Deny posture is read inside the held stripe so no SetDeny can slip between
	// the check and the insert. Order is fail-closed: global first.
	m.denyMu.RLock()
	_, killed := m.deny[denyKey(ScopeGlobal, "")]
	_, sessionDenied := m.deny[denyKey(ScopeSession, key)]
	m.denyMu.RUnlock()

	if killed {
		return SessionRow{}, ErrKillSwitchEngaged
	}
	if sessionDenied {
		return SessionRow{}, ErrSessionDenied
	}

	m.rowMu.Lock()
	defer m.rowMu.Unlock()

	// A live row (RESERVED or ACTIVE) is a double-book; a RELEASED tombstone is
	// not live, so its key may be reserved afresh. Re-reserving over a tombstone
	// that carried a container_name must free that name in the reverse index, so
	// a later session can claim the same runtime identity — this mirrors the
	// Postgres leg, whose upsert resets container_name to NULL on the same path.
	// Without this the in-memory boundNames index would leak and the two Store
	// implementations would disagree under the one shared conformance contract.
	if existing, ok := m.rows[key]; ok {
		if existing.State != StateReleased {
			return SessionRow{}, ErrReservationExists
		}
		if existing.ContainerName != "" {
			delete(m.boundNames, existing.ContainerName)
		}
	}

	row := SessionRow{
		Key:   key,
		Owner: owner,
		State: StateReserved,
	}
	m.rows[key] = row
	return row, nil
}

// Commit promotes the caller's RESERVED row to ACTIVE under the key stripe. It
// returns ErrReservationNotFound for an unknown key and ErrReservationConflict
// when the row is not RESERVED or the owner does not match.
func (m *memStore) Commit(ctx context.Context, key string, owner Identity) (SessionRow, error) {
	if err := ctxErr(ctx); err != nil {
		return SessionRow{}, err
	}

	stripe := m.keyStripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	m.rowMu.Lock()
	defer m.rowMu.Unlock()

	row, ok := m.rows[key]
	if !ok {
		return SessionRow{}, ErrReservationNotFound
	}
	if row.Owner != owner {
		return SessionRow{}, ErrReservationConflict
	}
	if row.State != StateReserved {
		return SessionRow{}, ErrReservationConflict
	}

	row.State = StateActive
	m.rows[key] = row
	return row, nil
}

// BindContainerName records the runtime container identity on the caller's row
// once, under the key stripe. It is write-once: ErrBindingExists if the row
// already carries a name or if containerName is already bound to another row. It
// returns ErrReservationNotFound for an unknown key and ErrReservationConflict on
// an owner mismatch.
func (m *memStore) BindContainerName(ctx context.Context, key string, owner Identity, containerName string) (SessionRow, error) {
	if err := ctxErr(ctx); err != nil {
		return SessionRow{}, err
	}

	stripe := m.keyStripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	m.rowMu.Lock()
	defer m.rowMu.Unlock()

	row, ok := m.rows[key]
	if !ok {
		return SessionRow{}, ErrReservationNotFound
	}
	if row.Owner != owner {
		return SessionRow{}, ErrReservationConflict
	}
	if row.ContainerName != "" {
		return SessionRow{}, ErrBindingExists
	}
	if boundTo, taken := m.boundNames[containerName]; taken && boundTo != key {
		return SessionRow{}, ErrBindingExists
	}

	row.ContainerName = containerName
	m.rows[key] = row
	m.boundNames[containerName] = key
	return row, nil
}

// Release moves the caller's row to the RELEASED tombstone under the key stripe.
// It is idempotent against an already-released row (returns the terminal row, no
// error, no double credit). It returns ErrReservationNotFound for an unknown key
// and ErrReservationConflict on an owner mismatch.
func (m *memStore) Release(ctx context.Context, key string, owner Identity) (SessionRow, error) {
	if err := ctxErr(ctx); err != nil {
		return SessionRow{}, err
	}

	stripe := m.keyStripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	m.rowMu.Lock()
	defer m.rowMu.Unlock()

	row, ok := m.rows[key]
	if !ok {
		return SessionRow{}, ErrReservationNotFound
	}
	if row.Owner != owner {
		return SessionRow{}, ErrReservationConflict
	}
	if row.State == StateReleased {
		// Already terminal: idempotent no-op, no double credit.
		return row, nil
	}

	row.State = StateReleased
	m.rows[key] = row
	return row, nil
}

// LiveSessions returns a snapshot of every reservation row currently in
// StateReserved or StateActive — the live set the boot reconciler reclaims from
// and the kill-switch force-kill-every step enumerates. It is the optional
// live-enumeration capability the registry.LiveLister seam type-asserts the Store
// to; the frozen Store interface is not widened by it.
//
// It takes rowMu only for the brief scan and copies each matching row into a
// freshly-allocated slice, so the returned snapshot neither aliases the row map
// nor holds the lock past the copy — matching the locking discipline of the
// other read paths in this file, which never hold rowMu across a side effect. A
// RELEASED tombstone is not live and is excluded, so a reconciler never tries to
// reclaim a row whose capacity was already returned. A cancelled context fails
// closed with ErrStoreUnavailable, exactly as every other method does.
func (m *memStore) LiveSessions(ctx context.Context) ([]SessionRow, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	m.rowMu.Lock()
	defer m.rowMu.Unlock()

	// Copy out under the lock: the returned slice is independent of the map, so a
	// later mutation cannot mutate a row the caller already read, and the lock is
	// released the instant the scan completes (the defer unlocks on return).
	live := make([]SessionRow, 0, len(m.rows))
	for _, row := range m.rows {
		if row.State == StateReserved || row.State == StateActive {
			live = append(live, row)
		}
	}
	return live, nil
}

// LookupSession reads the current row for key without the key stripe, race-safe
// under rowMu. It returns ErrReservationNotFound when no row exists.
func (m *memStore) LookupSession(ctx context.Context, key string) (SessionRow, error) {
	if err := ctxErr(ctx); err != nil {
		return SessionRow{}, err
	}

	m.rowMu.Lock()
	defer m.rowMu.Unlock()

	row, ok := m.rows[key]
	if !ok {
		return SessionRow{}, ErrReservationNotFound
	}
	return row, nil
}

// SetDeny writes a durable deny entry and engages it immediately. Re-setting an
// already-set scope/key is idempotent (the entry is overwritten with the new
// context). The global kill-switch normalizes its key to empty.
func (m *memStore) SetDeny(ctx context.Context, entry DenyEntry) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	if entry.Scope == ScopeGlobal {
		entry.Key = ""
	}

	m.denyMu.Lock()
	defer m.denyMu.Unlock()
	m.deny[denyKey(entry.Scope, entry.Key)] = entry
	return nil
}

// ClearDeny removes a durable deny entry by scope and key (empty key for
// ScopeGlobal), lifting it. Clearing an absent entry is idempotent.
func (m *memStore) ClearDeny(ctx context.Context, scope DenyScope, key string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	if scope == ScopeGlobal {
		key = ""
	}

	m.denyMu.Lock()
	defer m.denyMu.Unlock()
	delete(m.deny, denyKey(scope, key))
	return nil
}

// LoadDeny returns the full durable deny posture. A transient store failure
// returns ErrStoreUnavailable; the in-memory leg only fails closed on a
// cancelled context.
func (m *memStore) LoadDeny(ctx context.Context) ([]DenyEntry, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	m.denyMu.RLock()
	defer m.denyMu.RUnlock()

	entries := make([]DenyEntry, 0, len(m.deny))
	for _, e := range m.deny {
		entries = append(entries, e)
	}
	return entries, nil
}

// Charge atomically check-and-increments the counter cell for key under the
// quota cell stripe. It refuses with ErrQuotaExceeded — leaving the cell
// unchanged — when value+delta would exceed limit, including the first charge
// into an absent cell. A negative delta is never refused and saturates at zero.
func (m *memStore) Charge(ctx context.Context, key QuotaKey, delta, limit int64) (int64, error) {
	if err := ctxErr(ctx); err != nil {
		return 0, err
	}

	stripe := m.quotaStripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	m.quotaMu.Lock()
	defer m.quotaMu.Unlock()

	current := m.quota[key]

	if delta < 0 {
		// A release of previously charged capacity is never refused and the
		// counter never goes negative.
		next := current + delta
		if next < 0 {
			next = 0
		}
		m.quota[key] = next
		return next, nil
	}

	// Positive (or zero) delta is guarded against limit identically whether the
	// cell already exists or is being created fresh.
	if current+delta > limit {
		return 0, ErrQuotaExceeded
	}

	next := current + delta
	m.quota[key] = next
	return next, nil
}

// ReadQuota returns the current counter value for key without mutating it,
// race-safe under quotaMu. An absent cell reads as zero.
func (m *memStore) ReadQuota(ctx context.Context, key QuotaKey) (int64, error) {
	if err := ctxErr(ctx); err != nil {
		return 0, err
	}

	m.quotaMu.Lock()
	defer m.quotaMu.Unlock()
	return m.quota[key], nil
}
