# ocu-control

Control plane for [Open Computer Use](https://github.com/Wide-Moat/open-computer-use) (`next/v1` architecture).

One per deployment. The host-side `ocu-controld` daemon owns sandbox-session
lifecycle (create, route, destroy), admission and quota, the kill-switch and
session denylist, supervision and teardown of every per-session executor, and
audit emission. It dials into each guest; the guest never dials it.

The daemon boots kill-switch-first, binds two listeners (an operator Unix
socket and a gateway TCP endpoint), and runs the full create→destroy lifecycle
against a real `state.Store` (in-memory or Postgres) and a real Docker
`RuntimeProvider`. It mints the Storage-JWT, hash-chains every privileged action
into a durable OCSF audit trail, shuts down cleanly on SIGTERM, and scrubs the
host-owned handoff tree on teardown.

## Security posture

- **Host dials guest.** The guest never dials Control. The kill-switch is a
  host-initiated stop, not a cooperative guest action — an unreachable control
  channel grants the guest no new authority (NFR-SEC-01).
- **Kill-switch-first boot.** Boot loads the durable deny posture and engages
  DENY-ALL before any listener admits a create; an unreachable store at boot is
  fail-closed and binds nothing.
- **Two listeners, distinct endpoints.** An operator/lifecycle ingress and a
  gateway service-identity ingress. The kill-switch and force-kill exist only on
  the operator ingress; the gateway adapter is constructed with no operator seam
  and has no import path to the mint, so no gateway route reaches it
  (NFR-SEC-52).
- **A body id is a hint, never the authority.** A body-supplied session, tenant,
  or `container_name` seeds only the human-readable handle; the reservation key
  is host-derived from the attested caller identity (NFR-SEC-43).

## Storage-JWT custody

Control holds the Storage-JWT signing key. It mints and signs the weak,
`filesystem_id`-scoped session JWT and renders the JWKS the Egress trust-edge
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

## Quickstart

Build the daemon (static, no cgo):

```
make bin   # writes build/ocu-controld
```

Run it with the required flags the boot validator demands — omit any one and
the daemon refuses to boot fail-closed:

```
build/ocu-controld \
  -operator-listen   unix:///run/ocu-control/operator.sock \
  -gateway-listen    127.0.0.1:9466 \
  -runtime-tier      runc \
  -runtime-provider  docker \
  -workload-profile  untrusted \
  -jwt-signing-key   /run/secrets/storage-jwt-signing.key \
  -audit-sink        /var/log/ocu-control/audit.ocsf.jsonl
```

- `-runtime-tier` is `runc`, `gvisor`, or `firecracker` (deployment-wide, never
  per-request).
- `-runtime-provider` is `docker` or `k8s`.
- `-workload-profile` is `trusted_operator`, `internal_workforce`, or
  `untrusted` — the deployment-declared trust profile keying the admission
  matrix.
- `-jwt-signing-key` names a real file that must exist at runtime; there is no
  daemon-default key.
- `-audit-sink` names a writable path backed by a durable, fsync-on-write OCSF
  trail. `none`/`null` selects the non-durable sink behind a loud WARN.
- `-state-dsn` is empty by default (the in-memory minimal shelf); a non-empty
  DSN opens the Postgres `state.Store`.

[`deploy/docker-compose.yml`](deploy/docker-compose.yml) brings the daemon up
with one command, carrying every required flag under a read-only,
cap-dropped, seccomp-confined posture.

Run the gates:

```
make check   # fmt, vet, staticcheck, lint, spdx, contract, identity, seccomp, test
make test    # go test ./...
```

The integration legs need Docker. The real-binary e2e needs `OCU_CONTROL_BIN`
pointing at the built daemon (`make bin`, then export it). `make cover` enforces
the 91% coverage floor over `internal/`; set `OCU_TEST_DATABASE_URL` first so
the real-Postgres leg runs and its lines count.

## Architecture map

- [`docs/architecture.md`](docs/architecture.md) — the seams this repo builds:
  the listener split, host-dials-guest, the `RuntimeProvider` and `state.Store`
  seams, the teardown finalizer order, the storage boundary.
- [`docs/design-decisions.md`](docs/design-decisions.md) — the decisions taken
  behind those seams, with the rejected alternatives.
- [`docs/testing.md`](docs/testing.md) — the test layers, what each needs, and
  the coverage-floor policy.
- [`docs/ci.md`](docs/ci.md) — the CI gates and their blocking semantics.
- [`docs/requirements.md`](docs/requirements.md) — the invariant index keyed to
  the canon NFR rows.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to build, the gate table, contract
  vendoring discipline.
- [`SECURITY.md`](SECURITY.md) — the threat model and disclosure process.
- The canon component spec [`02-control-operator-api.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/02-control-operator-api.md)
  — purpose, the two-listener split, the invariants, the failure modes.

## What ships in v0.1

Docker is the v1 `RuntimeProvider` (runc and gVisor tiers). The Kubernetes and
Firecracker providers are `NotImplemented` behind the same seam. The frozen wire
surface is the vendored `contracts/control`, `contracts/exec`, and
`contracts/storage` schemas; the #205 operator-REST, proto, and SOAR-revoke
schemas under `contracts/openapi` and `contracts/proto` are **draft** and
deferred (see [`docs/rpc-versioning.md`](docs/rpc-versioning.md)).

## Boundary

This repository is carved out of [`ocu-sandbox`](https://github.com/Wide-Moat/ocu-sandbox),
which narrows to the per-session executor. The boundary is recorded in
[ADR-0017](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0017-control-plane-repo-boundary.md);
the component spec is [`02-control-operator-api.md`](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/components/02-control-operator-api.md).
Language is Go only ([ADR-0012](https://github.com/Wide-Moat/open-computer-use/blob/next/v1/docs/architecture/adr/0012-implementation-language.md)).
The in-guest agent is Rust and lives in `ocu-sandbox`, not here.

## License

FSL-1.1-Apache-2.0. See [`./LICENSE`](LICENSE). Each release converts to
Apache-2.0 two years after it ships. `LICENSE-APACHE` and `LICENSE-MIT` are
reference texts for dependency licenses, not the license of this software; see
[`NOTICE`](NOTICE) for third-party notices.
