<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Changelog

All notable changes to ocu-control are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Dates are
ISO-8601 (UTC).

## [Unreleased]

### Changed — mcp-key wire-freeze adoption (canon #318)

The canon froze the Artifact-2 hashed-key-set schema and the operator mcp-key
verbs; this change adopts the freeze end to end.

- **Vendored `contracts/mcp/mcp-key-set.schema.json`** byte-identical from the
  canon (rev 09b00fc) and added it to the contract-identity and ajv gates.
- **A2 golden byte-identity chain** — `TestWriteKeySetMatchesGolden` pins the
  exact bytes `WriteKeySet` publishes for a production-shaped record set
  (revoked and expired records proven omitted); CI ajv-validates that golden
  against the vendored canon schema, so a wire drift fails either leg.
- **Fail-closed mint validation** — `Engine.Create` refuses an empty tenant or
  deployment (`ErrTenantMissing` / `ErrDeploymentMissing`, 400 on the wire)
  before any side effect: the published record pins both fields with
  minLength 1, so admitting either empty would render a schema-invalid
  artifact. `occ mcp-key create` now requires `--deployment`, mirroring the
  canon create-request.
- **Operator-REST doc alignment** — the mounted mcp-key routes are documented
  in `contracts/openapi/operator-rest.openapi.yaml` with the canon-frozen
  request/response shapes (shown-once `raw_key`, idempotent 200-never-404
  revoke).

### Added — v0.2 admin read-API (ADR-0022, Track B)

The operator-console read-surface, built on top of the v0.1 spine. It is a
read-only projection of the reservation registry: it mints nothing, mutates
nothing, and adds no control-plane state. It is structurally separated from the
mutating operator surface — the read handler holds only a narrow enumerate port
and the deployment singletons, so it cannot reach Destroy, the kill-switch, the
denylist, or a quota override (NFR-SEC-26 mirror).

- **State enrichment behind the `LiveLister` seam** — `state.EnrichedSessionRow`
  carries the durable activation enrichment (`ReservedAt`, `ActiveAt`, `Caps`)
  alongside the registry row. The frozen `state.Store` core and `Commit`
  signature are untouched; the enrichment is additive (nullable Postgres columns,
  a parallel in-memory map) behind optional `registry.EnrichedLister` /
  `ActivationRecorder` seams.
- **Operator-plane read endpoints** — `GET /v1alpha/sessions` (enriched live
  list), `GET /v1alpha/sessions/{key}` (one row, uniform 404 for
  released/absent), and `GET /v1alpha/deployment` (the deployment-wide runtime
  tier and provider singletons). An unattested caller is refused 401 before any
  enumeration, exactly as a mutating call is.
- **Zero-dependency `/metrics` surface** — a hand-rolled Prometheus 0.0.4
  exposition: counts-by-state gauge (fail-quiet on a scrape read error),
  create/destroy counters, and a reserved→active histogram whose sum/count is the
  average-start-duration tile. Start duration uses a monotonic clock with a
  negative-time clamp (NFR-SEC-48).
- **Design-fenced lifecycle event seam** — a thin `lifecycle.LifecycleEvent` and
  an `EventPublisher` port with a nil-guarded, non-fatal publish, in support of a
  future admin live stream. The Server-Sent-Events surface itself is design-only
  (an unfrozen open question); the console polls the GET routes until the event
  contract freezes.

### Changed

- The operator-REST OpenAPI document is aligned to the routes the operator socket
  actually serves: all paths under `/v1alpha/`, the read-surface schemas merged,
  and two never-mounted handler routes dropped from the spec. The unmounted
  operator handlers stay machine-fenced by an exact allow-list test so they
  cannot be served before their wire route lands deliberately.

### Security

- The read import-boundary is a positive allow-list, not a denylist of a few
  known-bad type names: every field of the read handler must be one of the vetted
  read-only types, so a swap to a concrete type carrying mutators fails the guard
  the moment it is introduced.

---

## [0.1.0] — unreleased (held cut)

The v0.1 spine: the minimal control plane — a host-rooted local operator
credential, a host-local Storage-JWT signing key, the Docker `RuntimeProvider`,
an in-memory and a Postgres `state.Store`, and a file-system audit sink. The
two-listener split, the kill-switch-first boot, the admission/quota fail-closed
matrix, the Storage-JWT mint + JWKS, the in-guest control-RPC surface, and the
audit-before-ack privileged path. Verified against a live Postgres and real
Docker under the race detector.

This release is a held cut pending the owner's release decision; the tag is not
yet applied. The load-bearing invariants it establishes are recorded in
[`CONSTITUTION.md`](./CONSTITUTION.md).

[Unreleased]: https://github.com/Wide-Moat/ocu-control/compare/main...HEAD
