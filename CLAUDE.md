# Project Instructions — ocu-control

This repository is the **implementation** of the Open Computer Use control
plane (component-02). The **architecture and specifications** are the source of
truth and live in `Wide-Moat/open-computer-use` under `docs/architecture/`.
Do not re-decide here what an ADR already decided; if a decision must change,
it changes in the architecture repo first.

This repo is **public**.

## Read before implementing

- [`docs/architecture/components/02-control-operator-api.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/02-control-operator-api.md)
  — purpose, the two-listener split, the invariants, failure modes (P2 STRIDE rows).
- [`docs/architecture/adr/0012-implementation-language.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0012-implementation-language.md)
  — Go only for the host plane.
- [`docs/architecture/adr/0017-control-plane-repo-boundary.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0017-control-plane-repo-boundary.md)
  — the carve-out from `ocu-sandbox`; one-per-deployment Control vs `[1..N]` executor.
- [`docs/architecture/adr/0018-in-guest-control-rpc-endpoint.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0018-in-guest-control-rpc-endpoint.md)
  — the host-dialled control-RPC surface.
- [`docs/architecture/adr/0019-egress-exchanges-filestore-credential.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0019-egress-exchanges-filestore-credential.md)
  — the Egress trust-edge exchanges the weak JWT for the real filestore credential.
- `contracts/control/control-rpc.schema.json`, `contracts/exec/exec-channel.schema.json`,
  `contracts/storage/mount-config.schema.json` — the frozen wire surface vendored
  from the canon. The discriminator union, operation names, and the response
  envelope are pinned; deferred verbs stay deferred until the contract pins them
  — never invent a body here and code against it.

## Load-bearing rules

- The host dials the guest; the guest never dials Control. The kill-switch is a
  host-initiated stop, not a cooperative guest action — an unreachable control
  channel grants the guest no new authority (NFR-SEC-01).
- Kill-switch-first boot: load the denylist and kill-switch state and engage
  DENY-ALL before any listener admits a create.
- A body-supplied session / tenant / `container_name` id is a hint, never the
  authority. The binding is host-derived from the runtime-attested caller
  identity (NFR-SEC-43).
- Two listeners on distinct endpoints: an operator/lifecycle ingress and a
  gateway service-identity ingress. The kill-switch and force-kill exist only on
  the operator ingress; no gateway route reaches it (NFR-SEC-52).
- Storage-JWT custody: Control holds the signing key, mints the weak
  `filesystem_id`-scoped session JWT, and publishes a JWKS the Egress trust-edge
  validates against. It does NOT hold the real filestore credential and does NOT
  speak the filestore protocol; the mount runs inside the sandbox
  (`ocu-rclone-filestore`).
- Admission + quota run fail-closed before any host state exists. Runtime-tier is
  deployment-wide, never per-request. The provider is chosen behind the
  `RuntimeProvider` seam — no concrete container SDK import in control logic.
- Every privileged operator/SOAR action emits a chain-linked OCSF event before
  acknowledgement; the action is denied if the audit write fails (fail-closed).

## Writing discipline

- State facts in this project's own words. Specs, ADRs, and the frozen wire
  contracts are the only citable sources for behaviour; committed files never
  quote or name third-party material as the origin of an internal behaviour.
- All code, comments, commit messages, PR titles and descriptions, and docs
  are **English only**. No exceptions.

## License headers

Every new source file starts with:

```
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
```

(comment syntax per language). LICENSE = FSL-1.1-Apache-2.0; converts to
Apache-2.0 two years after each release. `LICENSE-APACHE` / `LICENSE-MIT` are
dependency reference texts, not ours.

## Git

- Identity: `developer@widemoat.ai`. Verify before committing.
- Conventional commits. End commit messages with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Branch off `main`; one PR per logical change. No merge without an explicit
  per-PR instruction.

## Build discipline

Minimal shelf first: a host-rooted local operator credential, a host-local
Storage-JWT signing key, the Docker `RuntimeProvider`, an in-memory `state.Store`,
and a file-system audit sink — zero external dependencies. Tests ship in the
same PR as the code, to the verification method the component's NFR row names
(property tests on the admission matrix and the reservation flow are mandatory,
not optional).

## CI gates (strict from commit 1)

Every PR must pass: secrets scan (gitleaks + trufflehog, any hit blocks),
naming denylist (lexicon job; the list is maintained outside the tree), SAST
(semgrep CRITICAL blocks), SCA (trivy CRITICAL blocks), conventional-commits.
Coverage, mutation, property, and perf gates wire in as the code lands.
