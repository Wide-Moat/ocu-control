<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# CI

The gates every PR clears, by workflow. All of it is Go: one module, no Rust
toolchain, no object-store rig. `make check` reproduces the merge-blocking
subset locally.

## go.yml — per-job

| Job | What it asserts | Local |
|---|---|---|
| `gofmt` | No unformatted Go file | `make fmt` |
| `vet` | No `go vet` finding | `make vet` |
| `staticcheck` | No `staticcheck` finding (pinned `2026.1`) | `make staticcheck` |
| `golangci` | The `.golangci.yml` security/correctness set (gosec, errorlint, bodyclose, …) | `make lint` |
| `test` | `go test ./...` passes | `make test` |
| `race` | `go test -race ./...` is data-race clean | `make test-race` |
| `coverage` | Line coverage over `./internal/...` ≥ the floor | `make cover` |
| `govulncheck` | No known-exploitable vuln reachable from the module | — |
| `schema` | Every vendored JSON-Schema contract compiles (ajv) | `make schema` |
| `checks` | SPDX header, maintainer identity, vendored-contract byte-identity | `make spdx contract identity` |

The `checks` job checks the canon out at the pinned revision so the
byte-identity gate enforces in CI. The pin lives in both the workflow and
`scripts/check-contract-identity.sh`; bump them together when re-vendoring.

## e2e.yml

`build-controld` builds the static daemon and publishes it as a same-run
artifact. `e2e` downloads it, runs the committed pre-bind smoke
(`scripts/e2e-smoke.sh`), then the `Integration|E2E` slice with `OCU_CONTROL_BIN`
set. `docker-build` builds the image single-arch to catch go.mod / Dockerfile
toolchain drift; it never pushes. This is a required, release-gating workflow —
no `continue-on-error`.

## mutation.yml

go-gremlins on the pure-logic leaf packages (`internal/admission`,
`internal/registry`, `internal/quota`, `internal/killswitch`), scoped in
`.gremlins.yaml`. Advisory (`continue-on-error`) until a stable efficacy
baseline; the ratchet plan is in the workflow header. The job skips a missing
dir with a notice.

## security.yml

Secrets scan (gitleaks + trufflehog, any hit blocks), SAST (semgrep, CRITICAL
blocks), SCA (trivy filesystem, CRITICAL blocks), the naming-denylist lexicon
job (denylist held as a repository secret; absent on forks, where it skips),
and conventional-commits on the PR title. Also runs on a weekly cron.

## codeql.yml

First-party CodeQL dataflow over the Go module on the `security-and-quality`
suite, with a manual `go build ./...` so build-tag-guarded packages are
extracted. Distinct from the semgrep SARIF upload in `security.yml`.

## release.yml

Triggers on `v*` tags. Validates the SemVer tag, waits for `security.yml` to be
green on the tagged commit, re-runs the full suite and the pre-bind smoke in the
release run (never cached green), builds and pushes the multi-arch GHCR image,
scans it (trivy CRITICAL blocks), generates a CycloneDX SBOM, signs every
artifact with cosign keyless, attests SLSA build provenance, and cuts the GitHub
Release.
