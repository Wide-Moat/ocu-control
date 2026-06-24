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

## Quality gates (as built)

Four quality gates landed on top of the security/coverage set above. Each is
blocking, pinned to an exact tool version, and ships a RED-when-neutered proof —
a script that plants a defect, asserts the gate fires, and restores the tree — so
a gate that guards nothing cannot pass review. The proofs run in CI alongside the
gates, not just locally.

- **Dead code** (`deadcode.yml`, `scripts/deadcode-gate.sh`): `deadcode -test
  ./...` over the whole build-plus-test graph; fails on ANY unreachable function,
  catching dead EXPORTS the package-local unused check cannot see. It gates on
  non-empty output, never on the tool's exit status. The `-test` flag keeps the
  deliberately-deferred operator handlers reachable from their own tests, so the
  clean baseline is literally empty.
- **Mutation score** (`mutation.yml`, `scripts/mutation-floor.sh`): go-mutesting
  on the pure-logic leaf packages (admission, killswitch, quota, registry) with a
  per-package score floor that ratchets UP only. It gates on the PARSED score (not
  the exit code, which is always 0) and fails closed on a no-score run — the
  anti-gremlins guard, since the retired gremlins tool was structurally blind on
  this module and reported a phantom 0%. Current floors: admission 1.0, killswitch
  0.8, quota 0.8, registry 1.0.
- **Doc prose** (`docs.yml`, `scripts/vale-gate.sh`): vale against the
  Architecture style — a banlist of marketing adjectives, AI-slop preamble
  phrases, and the AP-13 data-class-picks-substrate anti-pattern — blocking on the
  canon-critical docs and warning on the auxiliary set. The slop-scanner CLASS was
  DROPPED, not replaced one-for-one: no vetted Node-free ML-slop detector exists,
  and dropping in a substitute CLI would be fake-green in a new wrapper. A
  deterministic prose banlist is the honest gate instead. The `.vale.ini` and the
  Architecture style are vendored byte-identical from canon (one banlist across
  the fleet); a banlist change lands in canon first, never by editing `.vale/`
  here. lychee checks forward-reference (relative-link) integrity on the same .md.
- **License headers, contract identity, doc identity**: the SPDX header gate, the
  byte-identity check against the vendored canon contracts, and the stale-identity
  scan round out `make check`, the one-command pre-push gate that mirrors CI.
