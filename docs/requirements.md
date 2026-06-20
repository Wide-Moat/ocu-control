<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Requirements and defaults

Distilled from the architecture canon (component-02 spec, ADR-0012/0017/0018/0019,
the vendored contracts, and the NFR rows they cite) for the team building this
repo. The canon wins on any conflict; this file is a working index, not a second
source of truth. The full PRD lives in `.planning/` (gitignored, local-only).

## Invariants (build targets, each falsifiable)

| # | Rule | Source | Verification |
|---|---|---|---|
| 1 | Every route to create or manage a session enters through Control; no MCP-surface route resolves to a lifecycle/denylist/kill-switch route, and no rendered manifest grants the gateway a route to the operator ingress | NFR-SEC-52 | held by topology (operator = UDS, gateway = loopback, no Service/Ingress/NodePort); default-deny NetworkPolicy + policy-as-code CI gate is a fast-follow ([#1](https://github.com/Wide-Moat/ocu-control/issues/1)) |
| 2 | The host dials the guest; the guest never dials Control. The kill-switch is a host-initiated stop — an unreachable control channel grants the guest no new authority | NFR-SEC-01 | unit + e2e |
| 3 | Kill-switch-first boot: denylist and kill-switch state load and DENY-ALL engages before any listener admits a create | NFR-SEC-01 | e2e (pre-bind refusal) |
| 4 | A body-supplied session/tenant/`container_name` id is a hint, never the authority; the binding is host-derived from the runtime-attested caller identity | NFR-SEC-43 | property-test (forge-another-session) |
| 5 | The gateway service identity carries no operator scope; force-kill, denylist edit, and quota override are unreachable with that audience | NFR-SEC-26 | audience-to-route map test |
| 6 | Admission (workload-trust-profile × runtime-tier) and per-caller/per-tenant quota run fail-closed before any host state exists; excess is refused, not queued | NFR-SEC-38, NFR-COST-06 | property + per-profile admission test |
| 7 | Runtime-tier is deployment-wide, never per-request; an unknown tier/provider is refused, never defaulted | ADR-0003, component-02 | e2e (pre-bind refusal) |
| 8 | Control holds the Storage-JWT signing key, mints the weak `filesystem_id`-scoped session JWT, and publishes a JWKS; it does not hold the real filestore credential and does not speak the filestore protocol | ADR-0013, ADR-0019, NFR-SEC-25 | unit + contract-conformance |
| 9 | The kill-switch / revoke route holds its ≤30 s p99 SLA under saturation, on reserved capacity distinct from the create path | NFR-SEC-55 | perf (k6) |
| 10 | Every privileged operator/SOAR action emits a chain-linked OCSF event before acknowledgement; the action is denied if the audit write fails (fail-closed) | NFR-SEC-45 | unit-test |
| 11 | TTL and revocation windows run against a monotonic clock; a wall-clock setback neither extends a token nor defers a revoke | NFR-SEC-48 | clock-rollback harness |
| 12 | Teardown is host-driven and ordered (credential-revoke, egress-route-drop, writable-surface-scrub); a guest reply never substitutes, reorders, or marks it complete | NFR-SEC-65 | integration |

## Defaults (NFR-derived, configurable, not frozen)

| Knob | Default | Source |
|---|---|---|
| Runtime provider | `docker` (v1; behind the RuntimeProvider seam) | ADR-0012 |
| Runtime tier | deployment-declared (`runc` \| `gvisor` \| `firecracker`), never per-request | ADR-0003 |
| state.Store backing | in-memory (minimal shelf); Postgres behind the same seam later | design-decisions.md |
| Operator-auth substrate | host-rooted local credential (minimal shelf); customer-IdP-asserted (full shelf) | ADR-0004 |
| Storage-JWT signer | host-local signing key (minimal shelf); customer-PKI-rooted (full shelf) | component-02 shelf delta |
| Kill-switch p99 | ≤ 30 s, reserved capacity distinct from create | NFR-SEC-55 |

## Deliberately out of scope

- The agent loop and the model choice — they live in the calling client, not in
  Control. If a sandbox tool needs an LLM it reaches it as one allow-listed
  egress endpoint, never through a Control model abstraction.
- An admin web UI — a v1 non-goal. Ops is CLI + GitOps + Grafana.
- Storage scope enforcement — the Egress trust-edge and the storage engine
  enforce it on the exchanged credential; Control verifies no storage scope.
- The per-session executor and the in-guest agent — they are `ocu-sandbox`
  (Rust), a separate deployable Control drives over the host-dialled channel.

## Open questions (tracked in the architecture repo)

Gateway internal-token minimum scope and per-action operator authz
([#187](https://github.com/Wide-Moat/open-computer-use/issues/187)); measurable
no-customer-payload gate ([#149](https://github.com/Wide-Moat/open-computer-use/issues/149));
saturation/spill containment target
([#188](https://github.com/Wide-Moat/open-computer-use/issues/188));
trusted-time floor for JWT TTL and denylist propagation
([#185](https://github.com/Wide-Moat/open-computer-use/issues/185)).
