<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Architecture

How `ocu-controld` is shaped behind component-02. The canon owns the decisions;
this page records the seams this repo builds against and links the canon for
every claim it does not restate.

The authoritative spec is [`02-control-operator-api.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/02-control-operator-api.md):
purpose, the two-listener split, the invariants, and the P2 failure modes. The
boundary that made this a separate repo is [ADR-0017](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0017-control-plane-repo-boundary.md);
the language is Go only ([ADR-0012](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0012-implementation-language.md)).

## Listener split

Two listeners back the daemon on distinct endpoints: an operator/lifecycle
ingress and a gateway service-identity ingress. The kill-switch and force-kill
routes exist only on the operator ingress; no gateway route reaches it
(component-02 Boundaries; NFR-SEC-52). The scaffold takes both endpoints as
`-operator-listen` and `-gateway-listen`, validated and refused pre-bind before
either binds.

## Host dials guest

The host dials the guest; the guest never dials Control. Create, drive, and
teardown, plus the Storage-JWT delivery, all flow host→guest. The control-RPC
surface is host-dialled over a host-owned Unix socket
([ADR-0018](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0018-in-guest-control-rpc-endpoint.md));
the exec/PTY channel is a separate host-dialled WebSocket. The kill-switch is a
host-initiated stop, not a cooperative guest action — an unreachable channel
grants the guest no new authority.

## RuntimeProvider seam

Control drives per-session executor containers through a `RuntimeProvider`
interface, never a concrete container SDK. Docker is the v1 provider; Kubernetes
and Firecracker are future implementations behind the same seam. No
`docker/docker/client` import appears in control logic — the dependency lives
behind the interface so the create / start / inspect / stop / teardown call set
is one narrow contract the rest of the plane depends on. The deployment-wide
`-runtime-tier` (runc / gvisor / firecracker) is a separate axis from the
provider and is never chosen per-request.

## state.Store seam

The session registry, the denylist / kill-switch state, and the quota counters
sit behind a `state.Store` interface. The minimal shelf ships an in-memory
store; a Postgres-backed store lands later behind the same seam without touching
the lifecycle logic above it. Control is the sole custodian of this state — no
other component mutates it and the guest holds no handle that reaches it
(component-02 Invariants).

## Teardown finalizer order

Teardown is host-driven and ordered. The host executes credential-revoke,
egress-route-drop, and writable-surface-scrub regardless of any guest reply; a
guest that skips a cooperative shutdown phase or claims clean is overridden by
the host-executed steps (the control-RPC `Shutdown` verb is an advisory
fast-path, never a completion claim; see the vendored
`contracts/control/control-rpc.schema.json`). The finalizer authority is
NFR-SEC-65.

## Storage boundary

Control's storage job is narrow: mint the weak `filesystem_id`-scoped Storage-JWT,
sign it, publish a JWKS the Egress trust-edge validates against, and render and
deliver one mount-config per session into the guest over the host-only
provisioning push. Control does **not** perform the mount and does **not** speak
the filestore protocol.

It does not hold the real filestore credential: the Egress trust-edge validates
the weak JWT against Control's JWKS, strips it, and exchanges it (RFC 8693) at a
separately-named credential authority for the real credential, which never
reaches Control or the guest
([ADR-0019](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0019-egress-exchanges-filestore-credential.md)).
The mounting runs inside the sandbox in
[`ocu-rclone-filestore`](https://github.com/Wide-Moat/ocu-rclone-filestore); the
host-side filestore protocol client is
[`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore). The vendored
`contracts/storage/mount-config.schema.json` is the shape Control renders.
