# ocu-control

Control plane for [Open Computer Use](https://github.com/Wide-Moat/open-computer-use) (`next/v1` architecture).

One per deployment. The host-side `ocu-controld` daemon owns sandbox-session
lifecycle (create, route, destroy), admission and quota, the kill-switch and
session denylist, supervision and teardown of every per-session executor, and
audit emission. It dials into each guest; the guest never dials it.

## Storage-JWT custody

Control holds the Storage-JWT signing key. It mints and signs the weak,
`filesystem_id`-scoped session JWT and publishes a JWKS the Egress trust-edge
validates against. It does **not** hold the real filestore credential: the
Egress trust-edge exchanges the weak JWT for that credential at a separate
authority ([ADR-0019](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0019-egress-exchanges-filestore-credential.md)),
and that credential never reaches the guest.

The storage job here is narrow: mint the weak JWT and render and deliver one
mount-config per session into the guest. Control does **not** perform the mount
and does **not** speak the filestore protocol. The mount runs inside the
sandbox in [`ocu-rclone-filestore`](https://github.com/Wide-Moat/ocu-rclone-filestore),
which mounts the per-session files; the host-side filestore protocol client is
[`ocu-filestore`](https://github.com/Wide-Moat/ocu-filestore).

## Boundary

This repository is carved out of [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox),
which narrows to the per-session executor. The boundary is recorded in
[ADR-0017](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0017-control-plane-repo-boundary.md);
the component spec is [`02-control-operator-api.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/02-control-operator-api.md).
Language is Go only ([ADR-0012](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0012-implementation-language.md)).
The in-guest agent is Rust and lives in `ocu-sandbox`, not here.

Status: scaffolding. No implementation yet.

## License

FSL-1.1-Apache-2.0. See the upstream [LICENSE](https://github.com/Wide-Moat/open-computer-use/blob/main/LICENSE).
