<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Embedded seccomp profile — provenance

`default.json` is the deny-default seccomp profile (`defaultAction:
SCMP_ACT_ERRNO`) embedded into the Docker provider with `//go:embed` and applied
verbatim as the `seccomp=` `SecurityOpt` on every container the provider
materializes. It is the HOST-01 hardening reference reproduced behind the
`RuntimeProvider` seam: an explicit allowlist that admits the syscalls a sandbox
workload and the container runtime legitimately need (including the namespace
and mount calls the daemon uses to stage the per-session network) while
returning `EPERM` for everything else.

A minimal hand-written allowlist is not viable here: a profile that omits the
syscalls the runtime needs to set up a container's network namespace makes every
`ContainerStart` fail before the workload runs. The pinned upstream profile is
the deny-default posture that is both hardened and runnable, which is why it is
adopted verbatim rather than re-derived.

## Fail-closed contract

The provider `json.Compact`-validates this document at package init and refuses
to construct a `HostConfig` if it is absent or unparseable (`ErrSeccompProfileMissing`).
No container is ever created without this explicit profile — the provider never
falls back to the Docker daemon default. A malformed profile is a build/init
failure, not a silent downgrade.

## Provenance (pinned)

`default.json` is adopted third-party content, taken verbatim at a resolved
upstream commit (not a moving branch), so the exact bytes are reproducible and
tamper-evident.

- **Upstream source:** the moby project default seccomp profile.
- **Upstream repository + in-repo path:** `moby/profiles`, `seccomp/default.json`.
- **Upstream commit:** `836ae4d37ef2ec995c77c99fc55f5b5f3af3a897`
- **`sha256: 536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`**

The `sha256:` line is the tamper-evidence anchor — the digest of the exact
committed `default.json`. It must equal the output of, run in this directory:

```
shasum -a 256 default.json
```

Any later byte change diverges from this line and is therefore detectable. The
licence of this third-party content is recorded in the repository `NOTICE`, not
asserted as this project's original work.

## Drift policy

This file is the repository's pinned syscall posture. Upstream drift is adopted
deliberately, never implicitly: adopting a newer upstream profile means, in a
single commit, replacing `default.json`, updating the upstream commit and the
`sha256:` line above, and re-running the integration leg that proves a real
container still starts under the new profile. Do not edit the bytes in place.
