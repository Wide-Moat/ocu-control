<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Design decisions

Implementation choices this repo makes that do not rise to a canon ADR. Each is
reversible inside this module without changing a contract. A decision that
crosses a contract or another component belongs in an ADR in the architecture
repo, not here — if one of these grows that reach, it gets promoted.

## RuntimeProvider is a narrow interface, not the Docker SDK

The provider seam exposes only the lifecycle the control plane needs — a single
coarse `Materialize` (create network + container + start, atomically), the
canon-fixed teardown pair (`GracefulStop` / `ForceKill`), and a `Reconcile`
orphan-sweep — never the raw Docker SDK call set. Control logic depends on the
interface; the `docker/docker/client` import lives only in the one package that
implements it (CI greps the tree to keep `client.APIClient` out of every other
package). This inverts a Docker-weld: a Kubernetes or Firecracker provider is a
new implementation of the same interface, not a rewrite of the plane above it.
The seam sits *above* the whole SDK call set, distinct from the deployment-wide
runtime-*tier* selector (`-runtime-tier`), which is a separate axis. The exact
shape — why the per-session network create/remove pair lives *below* the seam,
and why the descriptor crossing the seam is substrate-neutral — is recorded
under "RuntimeProvider seam shape" below.

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

### RuntimeProvider seam shape: one coarse Materialize, network below the seam

create is ONE atomic Materialize(ctx, SessionSpec) -> (Sandbox, error), not the three discrete primitives (PrepareNetwork/ContainerCreate/ContainerStart) the losing on-disk design exposed. The deciding argument is the per-session network: under Docker it is a real Internal bridge, but under k8s there is no per-session bridge at all (a Pod's network is the cluster CNI plus a NetworkPolicy applied with the Pod). A fine triple forces the k8s impl to either expose a NetworkCreate it cannot honor or make it a zero-ID no-op — both leak the Docker object model onto the interface and write the lifecycle code above the seam against Docker's shape, the exact carve-out violation requirement 1 forbids. With Materialize coarse, the bridge create/remove pair and its ordering (the active-endpoints constraint: container removed before network) live entirely BELOW the seam inside the Docker impl, where the substrate knowledge belongs; the bridge name never appears on the interface and is a pure function of SessionName (ocu-net-<name>) so teardown re-derives it. The no-orphan invariant is internal rollback inside Materialize (remove container, then network) returning ErrMaterialize, which is also correct for k8s where Pod admission is atomic. On the produce-vs-neutral fork the seam carries a SUBSTRATE-NEUTRAL SessionSpec (MountIntent + EgressPolicy + ResourceCaps + HandoffMaterial + host-derived Name/Owner), never a docker bind string or an Envoy SDS bundle; each impl materializes the neutral fields. Materialize returns a typed EgressBinding inside the Sandbox so teardown DROPS the same route as a distinct verb, closing the ConfigureEgress(empty)-conflation bug the losing design shipped. This mirrors the existing internal/state discipline: the interface speaks domain values, the impl speaks its substrate.

### Runtime tier and runtime provider are orthogonal axes

RuntimeTier (-runtime-tier: runc | gvisor | firecracker) stays ORTHOGONAL to RuntimeProvider selection (-runtime-provider: docker | k8s); they do not fold. The provider is WHO materializes the spec (which SDK); the tier is the kernel-isolation strength the chosen provider asks its substrate for. They are independent axes — docker+gvisor and k8s+gvisor are both valid pairs — and the same TierFirecracker abort rule holds under either provider until that provider implements it. The tier is NOT a field on SessionSpec and NOT on the RuntimeProvider interface: it is deployment-wide and never per-request, so a provider is constructed bound to exactly one tier (it cannot be weakened by a request). Folding tier under provider would force a provider x tier product of impls and re-encode in the type system a constraint that is purely a per-backend support table; instead each provider carries its own tier mapping (the Docker impl maps TierRunc->runc, TierGvisor->runsc, and aborts TierFirecracker with ErrNotImplemented and ZERO substrate calls; a future k8s impl would map tiers to RuntimeClass). The provider reports which tiers it supports rather than the selector enumerating the legal pairs.

### Docker seccomp profile is the pinned moby deny-default, vendored verbatim

The Docker provider applies an embedded deny-default seccomp profile
(`internal/runtime/docker/seccomp/default.json`) as the `seccomp=` SecurityOpt on
every container, fail-closed (no container is created without it; a malformed
embed is `ErrSeccompProfileMissing`). The profile is the moby project default
profile adopted verbatim at a pinned upstream commit, not a hand-written
allowlist: a minimal allowlist that omits the namespace/mount syscalls the daemon
uses to stage a container's network namespace makes every `ContainerStart` fail
before the workload runs — a failure the fake-SDK unit tests cannot see and only
the real-Docker integration leg catches. The exact bytes are pinned by sha256 in
the profile's provenance README and re-checked by `scripts/check-seccomp-pin.sh`
so a silent drift of the enforced posture fails CI; an upstream re-pin updates the
profile, the README, and the script together in one commit and re-runs the
integration leg.

## Phase 3: lifecycle, ingress, admission, quota, registry

The Phase-3 lifecycle layer wires the state.Store and RuntimeProvider seams into a fail-closed create→destroy pipeline behind two listeners. The load-bearing decisions:

- scope-as-type vs scope-as-data: DECIDED scope-as-type via the unexported scopeWitness + OperatorSeam capability-by-possession. A gateway call to an operator-only method does not COMPILE. Rationale: a control plane whose scope separation is a runtime check is a latent EoP (judge's decisive axis); the deploy-time endpoint split and CI manifest grep are defense-in-depth, not the primary enforcement.
- identity-resolver shape: DECIDED a single ingress.IdentityResolver port with two concrete impls (operator PeerCredResolver = build-tagged Linux SO_PEERCRED, fail-closed off Linux; gateway cert-SAN resolver). AuthenticatedCaller carries the host-derived state.Identity + Channel and is the ONLY identity the Manager acts on. A body field never populates it; ErrUnattested refuses before any host state. The operator listener serves admin-API + SOAR over the Unix socket with SO_PEERCRED as the host-attested source; the SOAR signature is verify-then-mint so an unverifiable SOAR call yields no OperatorScope.
- admission-matrix-as-data: DECIDED the 3×3 matrix is a data table indexed by (profile, tier), Decide is a total pure lookup with a fail-closed ReasonUnknownCell default for any unknown enum. v1 GA = exactly 3 admit cells (trusted_operator×runc, trusted_operator×gVisor, internal_workforce×gVisor); the other 6 reject (3 pairing-rejected + 3 microVM-not-shipped). Property invariants: totality (no panic), exactly-3-admit over the full space, untrusted-never-on-shared-kernel (runc/gVisor), firecracker-column-never-admits (grafted from D3).
- rollback-unwind: DECIDED a single LIFO unwind stack (the []stage compensators), run under context.WithoutCancel(ctx) with a per-step bounded timeout — mirroring the runtime finalizer — so a client disconnect mid-create cannot abort rollback and strand an orphan. There is NO second cleanup path. A crash during unwind is recovered by Manager.Reconcile at next boot (provider.Reconcile force-kills substrate orphans; reclaimed RESERVED rows are Released + ReleaseConcurrency'd).
- reservation-key derivation: DECIDED registry.Key is an unexported-field type with no raw-string constructor; the only producer is DeriveKey(owner, host-minted-handle) using a structured length-prefixed-then-hashed derivation (namespace-escape-proof, collision-resistant). The body SessionHint seeds only the human-readable handle, never the namespace. This replaces an HMAC(deployment-secret,...) scheme to avoid the secret-rotation-orphans-live-keys hazard and makes 'a body id can never become the key' a compile fact.
- sole-custody enforcement: DECIDED registry.Custodian is the ONLY caller of Store.{Reserve,Commit,Release,BindContainerName}, enforced by a CI import-graph grep (mirroring the client.APIClient out-of-tree grep). lifecycle and killswitch route all registry mutation through it. LookupForCaller folds the owner-scoped read onto the same type and returns ErrNotOwned (indistinguishable from not-found) for non-owned/absent rows.
- audit-fail-closed-now: DECIDED ship the audit.AuditSink port + RecordingFake with a fault mode in Phase 3; the OCSF serializer is Phase 5 but the deny-on-emit-failure branch on every privileged op (create-commit, destroy, revoke-one, revoke-all, denylist-edit, quota-override) is exercised now.

The create path is an explicit ordered `[]stage` slice (resolve-identity → admit → quota → reserve → stage-handoff → materialize → commit → bind); each successful stage pushes a compensator onto a LIFO unwind stack, and any failure replays the stack in reverse under `context.WithoutCancel` with a per-step bounded timeout, so a refused or failed create leaves no row, no counter, no container, and no staged sock dir. The full pipeline is proven end-to-end against a real Postgres store and a real Docker provider together (the create→destroy e2e), and the no-orphan property is proven by a generated fault-injection at each stage.
