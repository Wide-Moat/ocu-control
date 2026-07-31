<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Memo: the Storage-JWT outlives no session longer than 15 minutes (#192)

Status: for ratification. Written from the control-plane source on 2026-07-26.

## What the issue says, and what the source says

Issue #192 records that the Storage-JWT has no refresh channel for an active
session longer than two hours. The first half is confirmed. The second half
understates the window by an order of magnitude.

The Storage-JWT lifetime is a compile-time constant of **15 minutes**
(`cmd/ocu-controld/main.go:715`, `const storageTTL = 15 * time.Minute`). It is
not a flag, so no deployment can widen it without a rebuild. Every session
therefore loses its storage credential 15 minutes after create, not after two
hours. A twenty-minute agent task is already past the end of its own credential.

## Why nothing replaces the token

The mint and the delivery both happen exactly once, inside the create pipeline:

- `stageMintStorageJWT` and `stageRenderPushMount` are consecutive stages of the
  create sequence (`internal/lifecycle/manager.go:381-382`).
- `mountcfg.Render` has one caller in the tree — that stage
  (`internal/lifecycle/stages.go:282`). No other code path renders or re-pushes a
  mount config.
- `Signer.MintStorageJWT` (`internal/cred/signer.go:225`) always stamps
  `exp = now + StorageTTL`. There is no exp-bump entry point and no route,
  RPC method, or contract operation that re-mints for a live session.

The three occurrences of `refresh`, `renew`, or `rotate` in the daemon are
unrelated to this: `cred.KeySet.Rotate` (`internal/cred/keyset.go:116`) rotates
the deployment **signing key** and is operator- or boot-driven, not per-session;
the `mcpkey` mentions describe the gateway's config refresh; and the JWKS
artifact comment records that v1 has no live rotation hook.

The idle reaper does not mask the problem, it selects for it. It reclaims only
rows whose `LastActivity` is older than the idle window
(`internal/lifecycle/manager.go:982-987`), so an idle session is torn down before
anyone notices the dead credential. The sessions that survive to hit this are
exactly the actively-working ones.

## What breaks, and where

The control plane cannot observe the failure, so this section states only what the
contract pins and marks the rest as requiring confirmation from the mount side.

The frozen mount-config contract puts the token in each mount entry as
`auth_token` and describes it as "short-lived, fixed-window, **no refresh**",
forwarded by the mount client as a static `Authorization: Bearer`, validated and
stripped at the egress edge, which exchanges it for the real filestore credential
(`contracts/storage/mount-config.schema.json:84`). So after `exp`:

1. The mount client keeps presenting the same expired bearer token, because it
   holds no other and has no way to be handed another.
2. The egress edge rejects it. The edge, not the filestore, is the enforcement
   point, so the real credential is never obtained for that request.
3. The failure surfaces inside the guest as a failing file operation on a mount
   that is still mounted. **Requires confirmation from component-05 / the
   filestore owner**: whether rclone's VFS returns `EIO` per operation, whether
   `vfs_cache_mode=writes` masks reads for `cache_duration_s`, and whether writes
   are lost or held. The control plane has no signal for any of it.

There is no metric, audit record, or session-state transition for a session whose
credential has expired. From Control's view the session stays ACTIVE and healthy.

## The two paths

**A. Re-provisioning push (recommended).** Keep the short fixed window, and
before `exp` re-mint and push a fresh mount config over the existing mount-plane
provisioning path. This is not a "refresh" in the sense the contract forbids:
nothing bumps an existing token's `exp`; the old token dies on schedule and a
new, separately-minted, separately-revocable token replaces it. The machinery
already exists — the same two stages the create path runs — so the work is a
control-side timer per live session plus the push, and the revoke index already
keys jti by session (`Signer.MintStorageJWT` records through `cred.Revoker`).

This path has one hard prerequisite outside this repo: the mount client must
accept a re-pushed mount config and swap the credential **without remounting**,
or the swap becomes a visible I/O interruption.

**That prerequisite is not met today.** The mount client's owner answered it
against `ocu-rclone-filestore` at `origin/main` (ccc1f7c), and the relevant
citations spot-check clean from here:

- The mount config is read exactly once, at process start, before the mount
  exists (`internal/mountcfg/mountcfg.go:74`, called from
  `cmd/ocu-rclone-filestore/run.go:74`).
- There is no re-read machinery at all: no `fsnotify`, no `SIGHUP`, no `SIGUSR`
  anywhere in non-test code — verified as a negative grep, not inferred.
  The only signals handled are `SIGTERM`/`SIGINT`, and both mean teardown.
- The credential is baked into a long-lived HTTP client: `authToken` is an
  unexported field assigned once in the constructor
  (`internal/brokerrpc/client.go:63`), read at one place that sets the bearer
  header. The code says so itself: "The credential is read once at construction;
  there is no refresh."

So a re-pushed config changes nothing — the running mount never looks at it.
Because the mount is served in-process (no child process, no rclone daemon), the
only way to swap the credential today is to restart the process, which tears the
FUSE mount down: the guest's open descriptors die and unflushed VFS cache goes
through teardown drain. That is not a credential rotation, it is an outage.

The same answer named the cheap seam, sized S on their side: `authToken` becomes
an atomically-swappable value behind the single `setAuthHeader` call every request
path already funnels through, plus a `SIGHUP` handler that re-reads the config.
With those two changes, path A works as intended — Control rewrites the config and
signals; the next request carries the new credential; the mount is never touched.

This does not change the recommendation, but it does change the sequencing: path A
is blocked on that seam landing, and until it does, Control's side would have
nowhere to push to.

**B. Documented session ceiling.** Declare that no session may outlive the
Storage-JWT window and enforce it by tearing the session down at `exp`.

Path B is not viable at the current constant. A 15-minute hard ceiling on every
session is not a product. Choosing B means first raising `storageTTL` to the
longest session the deployment intends to support and accepting a credential
window that wide, which is the security property the short window exists to
avoid, and which also widens the blast radius of a leaked token.

## Recommendation

Take path A, and treat the constant as a separate, smaller defect worth fixing
either way: a 15-minute credential window baked in as a compile-time constant is
not a deployment parameter in any useful sense, and the same code comment calls
it one. Exposing it as a bounded flag costs little and makes the window an
operator decision instead of a rebuild.

Sequence:

1. ~~Confirm whether a re-pushed mount config hot-swaps the credential without
   remounting.~~ **Answered: it does not.** See the prerequisite above.
2. The mount client's hot-swap seam lands first (their side, sized S: an
   atomically-swappable token behind the single header-setting call, plus a
   `SIGHUP` re-read). Until then Control has nowhere to push to, so building the
   Control half first would produce a re-push that silently changes nothing —
   the same "mechanism present, wiring absent" shape this repo has hit repeatedly.
3. Then the Control half: the pre-`exp` re-mint and push, with a metric for a
   failed re-push (the same reasoning as the reaper counters in #188 — a silent
   background failure that only surfaces as a broken session is not observable).

The fallback if that seam is refused is NOT "do nothing": it is a widened window
plus an enforced ceiling, and the ceiling then has to be ratified as a product
constraint rather than left as an implementation detail. That trade is worse on
every axis, which is why the seam is worth its S.

## What is still unknown

What the guest actually observes after `exp` — `EIO` versus `EACCES`, how far the
VFS cache masks it, whether writes are lost or held — is still unanswered. It does
not change the decision (the credential is dead either way and nothing replaces
it), so it is not worth a live experiment on its own; it changes only how the
failure is described to an operator. Worth folding into the first live test of the
re-push path rather than paying for separately.
