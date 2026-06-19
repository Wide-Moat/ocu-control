<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Design decisions

Implementation choices this repo makes that do not rise to a canon ADR. Each is
reversible inside this module without changing a contract. A decision that
crosses a contract or another component belongs in an ADR in the architecture
repo, not here — if one of these grows that reach, it gets promoted.

## RuntimeProvider is a narrow interface, not the Docker SDK

The provider seam exposes only the call set the lifecycle needs — create, start,
inspect, stop, force-kill, teardown, and network setup/teardown — as a single
interface. Control logic depends on the interface; the `docker/docker/client`
import lives only in the one package that implements it. This inverts a
Docker-weld: a Kubernetes or Firecracker provider is a new implementation of the
same interface, not a rewrite of the plane above it. The seam sits *above* the
whole SDK call set, distinct from the deployment-wide runtime-*tier* selector
(`-runtime-tier`), which feeds a single field and is a separate axis.

## state.Store is in-memory first

The session registry, the denylist / kill-switch state, and the quota counters
sit behind a `state.Store` interface. The minimal shelf ships an in-memory
implementation: zero external dependencies, the one-click-solo posture. A
Postgres-backed store lands behind the same interface later without touching the
lifecycle logic. Two consequences are accepted for the in-memory shelf: state is
process-local (the one-per-deployment single instance makes this safe — there is
no second custodian to reconcile with), and it does not survive a restart, so
durability of the denylist across restarts is a property the Postgres store
adds, not the in-memory one.

### Store row model and seam shape

The `state.Store` interface exposes a flat method set, not a transaction handle.
No Phase-1 flow spans two methods atomically, so atomicity is a per-method
guarantee the implementation owns — exposing a caller-orchestrated unit of work
would be premature generality. The four reservation mutators (`Reserve`,
`Commit`, `Release`, `BindContainerName`) each run their whole body under one
held per-key advisory lock; both impls funnel them through one internal
locked-transaction helper so "no mutation outside the lock" is structural, not a
convention.

The logical row model is three tables:

- **sessions** — `key` (host-derived reservation key, the advisory-lock subject
  and primary key) · host-derived owner (tenant + caller) · `state`
  (RESERVED → ACTIVE → RELEASED) · `container_name` (recorded data, `UNIQUE`,
  never the authority). `RELEASED` is a tombstone, never a `DELETE`, so a
  released row stays distinguishable from a never-reserved one (the no-orphan
  accounting and later-phase teardown-audit correlation both need the terminal
  record). The primary key on `key` is the durable double-book guard behind the
  lock.
- **denylist** — `(scope, key)` primary key. The global kill-switch is the
  single `scope=GLOBAL, key=''` row; a per-session deny is one `scope=SESSION`
  row per key. There is no separate kill-switch table: `SetDeny` / `ClearDeny` /
  `LoadDeny` are the same three calls for both postures, which is the
  deny-durability-split-by-scope requirement expressed as distinguishable rows.
- **quota_counters** — `(dim, scope_id)` primary key, one cell per dimension and
  billed identity. `container_name` and the windowed dimensions never make the
  Store do time math (see below).

### Advisory-lock key and the two lock domains

The reservation lock keys on `hash64(key)`: Postgres uses
`pg_advisory_xact_lock(hashtextextended(key, 0))` (auto-released at COMMIT /
ROLLBACK, so a panicked path leaks no lock); the in-memory sibling uses a keyed
`sync.Mutex` over the **same** `hash64(key)`, so the property and race tests
behave identically on both legs by construction. `Charge` uses a **distinct**
lock domain keyed on `hash(dim, scope_id)`, so reservation contention and quota
contention never cross.

### Quota windows are caller-computed opaque labels (the monotonic seam)

`QuotaKey.Window` is an opaque string the admission gate (Phase 3) derives
through the injected `Clock` — a truncated-minute / truncated-day bucket label.
The Store stores one counter cell per `(dim, scope_id, window)` and does **zero**
time math: a window rollover is "a new label is a new cell", never a
persisted-timestamp subtraction. This is the structural enforcement of the
trusted-time invariant (NFR-SEC-48): because a loaded timestamp loses its
monotonic reading across a `TIMESTAMPTZ` round-trip, no later-phase TTL /
revocation comparison may subtract a DB-loaded timestamp from `Clock.Now()`; all
window and TTL math uses the opaque label and durations measured between two
in-process `Clock` readings. A clock-rollback harness asserts that a wall-clock
setback moves no window boundary.

### Open: concurrent-sessions gauge coupling

`DimConcurrentSessions` lives in a separate lock domain from the reservation row,
so a crash between a successful `Reserve` and its counter increment can drift the
free-running gauge over the milestone. The caller contract is
exactly-one-increment-per-`Commit`, exactly-one-decrement-per-`Release`,
negative-delta-saturates-at-zero. Whether to reconcile the gauge from the live
row count at boot (rather than trusting the free-running counter) is an open
correctness decision to settle before Phase 3 wires admission; the tombstone row
model already preserves the data a reconcile would read.

### Deferred: stale-reservation reaper

`Release` is a tombstone, not a delete, so old `RELEASED` rows accumulate. A
boot/background reaper that evicts them (and the `reserved_at` age column it
needs) is deliberately **not** in the Phase-1 interface — no Phase-1 requirement
reads a reservation's age, and adding an age column now would invite the
"subtract a loaded timestamp from `Clock.Now()`" defect the monotonic seam
forbids. The reaper lands with the phase that builds tombstone aging.

## Two listeners, two endpoints, no shared mux

The operator/lifecycle ingress and the gateway service-identity ingress are
separate listeners on separate endpoints, not one listener with route-based
authorization. The kill-switch and force-kill routes exist only on the operator
ingress, and the separation is the enforcement: a gateway caller cannot reach an
operator route because it cannot reach the operator endpoint, not merely because
a route check denies it. This makes the NFR-SEC-52 reachability property a
deploy-time fact (rendered manifests grant no gateway route to the operator
ingress) rather than a runtime branch.

## Pre-bind refusal over post-bind validation

The daemon validates its full invocation and refuses before it binds either
listener: a missing required flag, an unknown runtime tier or provider, and the
kill-switch-first gate (a create presented at startup is refused before any
listener admits it). A refusal therefore leaves no listener and no socket, which
is what `scripts/e2e-smoke.sh` asserts. The alternative — bind, then reject bad
requests — would leave a window where a half-configured plane is reachable.
