<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Testing

How the suite is layered, what each layer needs, and the coverage-floor policy.

Questions or issues: developer@widemoat.ai

## Quick start

```sh
make check   # full local gate: fmt + vet + staticcheck + lint + spdx + contract + identity + test
```

`make check` mirrors every merge-blocking gate the CI `go` workflow runs. It
loud-skips the real-binary e2e leg if `OCU_CONTROL_BIN` is unset — the skip
message names the missing variable.

## Test taxonomy

| Layer | What it covers | Needs |
|---|---|---|
| Unit | One package's logic in isolation | nothing external |
| Property | Invariants over generated inputs (rapid) on the admission matrix and the reservation flow — mandatory where the NFR row names them | nothing external |
| Integration | A seam wired to a real dependency — the RuntimeProvider against a real container runtime, the state.Store against its backing store | a container runtime (Docker), not an object store |
| E2E | The real `ocu-controld` binary, end to end | the built binary via `OCU_CONTROL_BIN` |

The control plane has no object-store backend, so there is no MinIO/S3 rig and
no live-S3 leg. The integration leg that needs an external service needs a
**real container runtime** (runc via Docker), because the RuntimeProvider drives
real containers — not a mock. `deploy/docker-compose.test.yml` stages that
runtime; the integration package that consumes it lands with the provider PRs.

## Race detector

The daemon is concurrency-heavy: the admission gate, the per-session
supervisor, the host-dialled channels, and signal-driven shutdown all run
concurrently. A silent data race there is a correctness hole line coverage
cannot see, so the whole suite runs under `-race` in CI (`go / race`) and
`make test-race` locally.

## Real-binary e2e

```sh
CGO_ENABLED=0 go build -trimpath -o ocu-controld ./cmd/ocu-controld
export OCU_CONTROL_BIN=$PWD/ocu-controld
go test -run 'Integration|E2E' ./... -v -timeout 600s
```

`scripts/e2e-smoke.sh` asserts the four pre-bind refusals against that binary: a
missing required flag is named; an unknown `-runtime-tier` / `-runtime-provider`
is refused, never defaulted; and a create presented at startup is refused before
any listener binds (kill-switch-first, NFR-SEC-01), with no socket left behind.

## Coverage floor

The CI `coverage` job measures line coverage over the **production** `internal/`
packages — `cmd/` is a thin wiring shim and is excluded, and so is
`internal/state/statetest` (the shared conformance-suite test-support package,
whose `t.Fatalf` error branches never execute on a green pass and would deflate
the denominator). The job runs with a Postgres service container and
`OCU_TEST_DATABASE_URL` set, so the Postgres `state.Store` leg is executed for
real and its lines count.

The floor is **91%** — `floor(first-measured) - 1` against the 92.9% the first
logic packages (`internal/state`, `internal/state/postgres`, `internal/boot`)
measured with the Postgres leg live. It is a ratchet, never lowered: raise it as
coverage improves. Ship tests in the same PR as the code. `make cover` enforces
the same floor locally; set `OCU_TEST_DATABASE_URL` first or the Postgres leg
live-skips and its lines read as uncovered.
