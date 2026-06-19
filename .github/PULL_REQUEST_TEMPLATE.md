# Pull Request

## Summary

<!-- One or two sentences describing what this PR changes and why. -->

## Checklist

All items must be satisfied before requesting review. The CI gates listed
below are **strict from commit 1** and will block merge if they fail.

### Source quality

- [ ] Every new source file starts with the two-line SPDX header
  (`# SPDX-License-Identifier: FSL-1.1-Apache-2.0` and copyright line),
  using the comment syntax of the language (`make spdx` / `scripts/check-spdx.sh`).
- [ ] Code is formatted (`make fmt` — `gofmt -l .` reports no unformatted files).
- [ ] `go vet ./...` passes (`make vet`).
- [ ] `staticcheck ./...` passes with the pinned version (`make staticcheck`).
- [ ] `govulncheck ./...` reports no known-exploitable vulnerabilities
  (CI `govulncheck` job).

### Tests

- [ ] Tests are included in this PR alongside the code they cover
  (no implementation-without-tests merges).
- [ ] `go test ./...` passes locally (`make test`).
- [ ] The internal coverage floor is not regressed (`make cover`).
  The floor never decreases to accommodate new code; it ratchets up.
- [ ] Race detector clean: `go test -race ./...` passes (`make test-race`).

### Security gates (CI-enforced)

- [ ] Secrets scan: no credentials or tokens in the diff
  (CI: gitleaks + trufflehog, any hit blocks).
- [ ] SAST: no CRITICAL semgrep findings (CI: semgrep CRITICAL blocks).
- [ ] SCA: no CRITICAL supply-chain vulnerabilities (CI: trivy CRITICAL blocks).
- [ ] Naming denylist: diff contains no project-prohibited terms
  (CI: lexicon job; terms maintained as a repository secret).

### Documentation and identity

- [ ] Commit title follows Conventional Commits (`type(scope): description`).
- [ ] Commit message ends with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` if AI-assisted (project convention).
- [ ] Docs updated if observable behavior changed (README, CONTRIBUTING, architecture ADR if applicable).
- [ ] All text in code, comments, commit messages, and docs is English only.
- [ ] No retired maintainer address (`make identity` / `scripts/check-doc-identity.sh` — green).
- [ ] No provenance or denylist terms: content states facts in the project's own words; no reference to upstream internals or their origin.

### Scope and branch hygiene

- [ ] Branched off `main`; represents one logical change.
- [ ] `make check` (full local gate: fmt + vet + staticcheck + spdx + contract + identity + test) ran cleanly before pushing.
