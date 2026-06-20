<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# RPC-surface versioning (NFR-IC-04)

The control-plane RPC surface is versioned. A breaking change to the
operator/gateway wire surface requires a **MAJOR** version bump and a deprecation
header on the superseded route; CI enforces this so a breaking delta cannot merge
unversioned.

## What the gate is today

The operator-REST / proto wire schemas are a **deferred follow-up (#205)**. The v1
control plane ships its wire surface as the frozen JSON-Schema contracts vendored
under `contracts/` — `control-rpc`, `exec-channel`, `mount-config`, and the
`audit-fanin` AsyncAPI. None of those is a proto or OpenAPI surface that `buf
breaking` or `oasdiff` can run a breaking-change diff against.

So the gate is wired now as a **clearly-scoped no-op-until-schemas**:

- `scripts/rpc-version-check.sh` detects whether a diffable surface exists
  (a `buf.yaml`/`buf.gen.yaml` proto module, or `contracts/operator/openapi.yaml`).
- When none is present, it prints a notice and exits 0 — the gate is green from
  commit 1 and does **not** fabricate a schema just to have something to diff.
- `.github/workflows/rpc-version.yml` runs that script on every push and PR,
  passing the merge base as the diff target.

This keeps the gate honest: it is committed, runs, and stays green, rather than
being a placeholder that someone has to remember to add later.

## What the gate becomes when the schemas land

The check enforces automatically the moment a diffable surface is committed — no
workflow edit is needed:

| Surface committed | Tool the gate runs | Failure |
|---|---|---|
| `buf.yaml` / `buf.gen.yaml` (proto) | `buf breaking --against <base>` | a breaking proto delta |
| `contracts/operator/openapi.yaml` | `oasdiff breaking <base> <head> --fail-on ERR` | a breaking OpenAPI delta |

A failure means the surface changed incompatibly without a MAJOR bump. The fix is
to bump the surface version and carry a deprecation header on the removed/changed
route, not to suppress the gate.

## TODO when #205 lands

1. Commit the operator RPC schema (proto module under a `proto/` tree with a
   `buf.yaml`, or `contracts/operator/openapi.yaml`) alongside the route handlers.
2. Install the matching CLI in `rpc-version.yml` (`bufbuild/buf-setup-action` for
   buf, or the `oasdiff` release binary) — the script already fails loudly if the
   CLI is missing once a surface exists, so the wiring cannot silently no-op.
3. Add the surface-version constant + deprecation-header convention to the operator
   ingress, and a row to `docs/ci.md` for the now-enforcing job.
