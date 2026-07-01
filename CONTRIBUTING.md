# Contributing to ocu-control

Thank you for your interest in contributing. This document describes the
real gates every contribution must clear, the workflow to follow, and the
local commands that mirror CI exactly.

Questions or help: **developer@widemoat.ai**

---

## Quick orientation

`ocu-control` is the control plane of Open Computer Use (component-02): the
one-per-deployment host-side daemon that owns sandbox-session lifecycle,
admission and quota, the kill-switch and session denylist, custody of the
Storage-JWT signing key, and supervision and teardown of every per-session
executor. Architecture decisions live in
[`Wide-Moat/open-computer-use`](https://github.com/Wide-Moat/open-computer-use)
under `docs/architecture/`. If a decision must change, it changes there
first — never by unilateral code change here.

---

## License

This project is licensed under **FSL-1.1-Apache-2.0**. Two years after each
release the license converts automatically to Apache-2.0. See [LICENSE](./LICENSE).

### Required SPDX header on every new source file

Every new source file must begin with a two-line SPDX header, using the
comment syntax of the language:

```
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
```

For Go files use `//` comments; for shell scripts and Make use `#`; for
HTML/XML use `<!-- -->`. The CI `checks / SPDX header presence` job
(`scripts/check-spdx.sh`) fails the PR if the header is absent from any
in-scope file. Run `make spdx` locally to verify before pushing.

---

## Workflow

1. **Branch off `main`** — create a focused branch for your change.
2. **One PR per logical change** — do not bundle unrelated work.
3. **Tests in the same PR** — new code ships with tests; the coverage floor
   is a ratchet (see [Coverage floor](#coverage-floor-ratchet)). PRs that
   lower coverage are rejected.
4. **No merge without review** — a maintainer must approve before merge.
5. **No force-push to `main`** — the branch is protected.

---

## Commit format

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
The CI `security / conventional-commits` job checks every PR title against
the spec (types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`,
`perf`, `style`).

Every commit message must end with the Co-Authored-By trailer exactly as
shown:

```
feat(admission): add the runtime-tier admission matrix

Short prose body explaining why, not what.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

Include the `Co-Authored-By` line when the commit was produced with AI
assistance. If it was not, omit it.

---

## Writing discipline

- **English only** — all code, comments, commit messages, PR titles and
  descriptions, and documentation. No exceptions.
- **Documentation standard** — prose docs (package READMEs, architecture
  pages, wire references) follow [docs/documentation-standard.md](docs/documentation-standard.md):
  name code by identifier rather than line coordinate, let structure earn its
  shape, and state each fact once.
- **Project's own words** — state facts as this project knows them. Do not
  name any third-party system or upstream project as the origin of a
  behaviour, design choice, or implementation detail. Cite public open-source
  repositories by their public GitHub URL when relevant; do not attribute
  design provenance to proprietary or unpublished sources.
- **Naming denylist** — the CI `security / lexicon` job greps the committed
  tree against a maintained denylist of terms that must not appear. The
  denylist itself is kept outside the public tree (it is a repository secret).
  If your PR fails the lexicon gate, the CI output will show the file and
  line number but not the denied term itself — contact a maintainer for
  guidance.

---

## Running the gates locally

`make check` is the one-command pre-push gate. It mirrors every job the CI
`go` workflow runs on a pull request:

```sh
make check
# runs: fmt + vet + staticcheck + lint + spdx + contract + identity + test
```

Individual targets:

| Target | What it runs | CI job |
|---|---|---|
| `make fmt` | `gofmt -l .` (fails if unformatted) | `go / gofmt` |
| `make vet` | `go vet ./...` | `go / vet` |
| `make staticcheck` | `staticcheck ./...` @ `2026.1` | `go / staticcheck` |
| `make lint` | `golangci-lint run` (`.golangci.yml`) | `go / golangci` |
| `make mutation` | go-gremlins mutation test (advisory) on the pure-logic packages | `mutation / gremlins` |
| `make test` | `go test ./...` | `go / test` |
| `make test-race` | `go test -race ./... -timeout 600s` | `go / race` |
| `make cover` | Coverage over `./internal/...`, floor enforced | `go / coverage` |
| `make spdx` | SPDX header check | `go / checks / SPDX header presence` |
| `make contract` | Vendored contract identity check | `go / checks / vendored contract identity` |
| `make schema` | ajv compile of every vendored JSON-Schema contract | `go / checks / schema compile` |
| `make identity` | Maintainer identity check | `go / checks / maintainer identity` |

Prerequisites: Go >= 1.26 (match `go.mod`), GNU make, Node.js (for `make schema`,
which runs `npx ajv-cli`), Docker (for the runtime-provider integration legs as
they land).

Install the two pinned linters once:

```sh
go install honnef.co/go/tools/cmd/staticcheck@2026.1
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

`golangci-lint` (`.golangci.yml`) is the structural meta-linter: beyond the
single-purpose `go / vet` and `go / staticcheck` gates it runs the security and
correctness set this daemon needs — `gosec`, `errorlint`, `bodyclose`, and
peers. Its config-level exclusions are scoped and commented; do not add bare
`//nolint` to source.

### Gated leg that loud-skips without extra setup

The real-binary e2e leg requires `OCU_CONTROL_BIN` to point to a built daemon
binary; without it the `Integration|E2E` slice loud-skips with an explicit
message — no silent pass:

```sh
CGO_ENABLED=0 go build -trimpath -o ocu-controld ./cmd/ocu-controld
export OCU_CONTROL_BIN=$PWD/ocu-controld
```

The composed pre-bind smoke (`scripts/e2e-smoke.sh`) runs against that binary in
CI and asserts the four refusals: a missing required flag is named; an unknown
`-runtime-tier` / `-runtime-provider` is refused, never defaulted; and a create
presented at startup is refused before any listener binds (kill-switch-first).

---

## Coverage floor ratchet

The CI `go / coverage` job measures line coverage over the production
`internal/` packages (the control plane's real logic; `cmd/` is a thin wiring
shim and `internal/state/statetest` is the shared conformance-suite support
package, both excluded). The job runs with a Postgres service container and
`OCU_TEST_DATABASE_URL` set, so the Postgres `state.Store` leg counts. The floor
is **91%** — `floor(first-measured) - 1` against the 92.9% first measurement
(see [`docs/testing.md`](docs/testing.md)).

The floor is a ratchet: it is never lowered. New code ships with tests in the
same PR. When a later PR raises measured coverage, raise the floor to match. Do
not open a PR that lowers the floor.

Run `make cover` locally to measure coverage and enforce the floor before
pushing.

Property tests on the admission matrix and the reservation flow are mandatory
where the relevant NFR rows name them — not optional extras.

---

## Contract vendoring discipline

The four frozen wire contracts (`contracts/control/control-rpc.schema.json`,
`contracts/exec/exec-channel.schema.json`,
`contracts/storage/mount-config.schema.json`, and
`contracts/audit/audit-fanin.asyncapi.yaml`) are vendored copies of the
canonical contracts in `Wide-Moat/open-computer-use`. They must be
byte-identical to the canon.

The CI `go / checks / vendored contract identity` job (`scripts/check-contract-identity.sh`)
checks this parity on every PR. Do not hand-edit the vendored contracts. If
the canon changes, update the vendored copies to match exactly and verify
with `make contract`. The pinned canon revision is recorded in the script.

The discriminator union, operation names, and the response envelope in these
contracts are pinned. Deferred verbs in the canon stay deferred here too —
never invent a body and code against it.

---

## CI gates summary

Every PR must clear all of the following CI jobs before merge:

| Gate | Workflow / job | Blocks on |
|---|---|---|
| Format | `go / gofmt` | Any unformatted Go file |
| Vet | `go / vet` | `go vet` findings |
| Static analysis | `go / staticcheck` | `staticcheck` findings |
| Meta-linter | `go / golangci` | `golangci-lint` findings (`.golangci.yml`) |
| Unit tests | `go / test` | Any test failure |
| Race detector | `go / race` | Data race detected |
| Coverage floor | `go / coverage` | Coverage below the floor over `./internal/...` |
| SPDX header | `go / checks / SPDX header presence` | Missing header on any in-scope source file |
| Maintainer identity | `go / checks / maintainer identity` | Stale address in tracked files |
| Vendored contract | `go / checks / vendored contract identity` | Contract not byte-identical to canon |
| Schema compile | `go / checks / schema compile` | A vendored JSON-Schema contract does not compile |
| Naming denylist | `security / lexicon` | Denied term found in tree |
| Secrets scan | `security / secrets-gitleaks` | Any secret detected by gitleaks |
| Secrets scan | `security / secrets-trufflehog` | Any secret detected by trufflehog |
| SAST | `security / sast-semgrep` | CRITICAL semgrep finding |
| Dataflow analysis | `codeql / analyze` | CodeQL `security-and-quality` finding on Go |
| SCA | `security / sca-trivy-fs` | CRITICAL trivy finding |
| Conventional commits | `security / conventional-commits` | PR title not in Conventional Commits format |
| Real-binary e2e | `e2e / e2e` | Daemon smoke or Integration/E2E failure |

Additionally, `govulncheck` (`go / govulncheck`) runs on every PR and fails
on known-exploitable vulnerabilities reachable from this module.

The `mutation / gremlins` job (go-gremlins) runs on every PR and on a weekly
cron, scoped to the pure-logic leaf packages (`internal/admission`,
`internal/registry`, `internal/quota`, `internal/killswitch`). It measures
assertion strength
— it rewrites covered source and re-runs the suite, so a surviving mutant marks
a line the tests execute but do not assert on, a gap line coverage cannot see.
It is **advisory** (`continue-on-error`): it surfaces the efficacy summary in
the job log but does not block merge yet. The scope lives in `.gremlins.yaml`.
Run `make mutation` locally to reproduce it. The ratchet plan (a threshold
floor, then dropping the advisory flag) is recorded in
`.github/workflows/mutation.yml`.

Security workflow jobs also run on a weekly cron schedule against `main`.

---

## Reporting security vulnerabilities

Do not open a public issue for a suspected vulnerability. Use the private
reporting channel described in [SECURITY.md](./SECURITY.md).

---

## Contact

Maintainer: **developer@widemoat.ai**
