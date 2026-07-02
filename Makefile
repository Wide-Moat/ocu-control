# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Local development gate — mirrors CI verbatim.
#
# Every target runs the same commands that .github/workflows/go.yml and e2e.yml
# run; `make check` is the one-command pre-push gate.  Where CI uses
# actions/setup-go the equivalent is the host Go toolchain, so the Go version
# must match go.mod (currently 1.26.4).
#
# Prerequisites: Go >= 1.26, GNU make (or compatible POSIX make), Docker
# (required only for the runtime-provider integration legs, not for the unit
# gate).

# Go version recorded in go.mod (keep in sync when go.mod changes).
GO_VERSION := 1.26.4

# Staticcheck version pinned in CI (go.yml install step).
STATICCHECK_VERSION := 2026.1

# golangci-lint version pinned in CI (go.yml golangci job + go install fallback).
GOLANGCI_LINT_VERSION := v2.12.2

# avito-tech/go-mutesting mutation tester version pinned in CI (mutation.yml
# install step). No semver tag exists upstream, so the commit pseudo-version IS
# the pin (commit 48d0401f00fb). go-mutesting replaced go-gremlins, which is
# structurally blind on this module's comment-led go.mod (it scored a phantom 0%).
GO_MUTESTING_VERSION := v0.0.0-20251226130216-48d0401f00fb

# golang.org/x/tools/cmd/deadcode version pinned in CI (deadcode.yml install step).
GO_DEADCODE_VERSION := v0.38.0

# errata-ai/vale version pinned in CI (docs.yml install step). vale is a Go single
# binary, installed with the same go-install pin model as deadcode/go-mutesting —
# no Node, no slop-scanner CLI. The slop-scanner CLASS was dropped (no vetted
# Node-free ML detector exists); a deterministic prose banlist is the gate instead.
VALE_VERSION := v3.15.1

# Coverage floor (matches the awk assertion in go.yml). The first logic
# packages (internal/state, internal/state/postgres, internal/boot) measured
# 92.9% over the production packages with a live Postgres; the floor is
# floor(measured)-1. Ratchet up as coverage improves; never lower it. The
# measurement EXCLUDES internal/state/statetest (a test-support package whose
# t.Fatalf error branches never run on a green pass and would deflate the
# denominator) and runs with the Postgres leg live (OCU_TEST_DATABASE_URL set),
# so the number reflects real production-code coverage, not a methodology
# artifact.
COVERAGE_FLOOR := 91

.PHONY: help build bin dev-secrets test test-race cover spdx contract identity seccomp schema vet fmt \
        staticcheck lint deadcode vale mutation check

# ── help ────────────────────────────────────────────────────────────────────

help: ## Print this target list
	@printf '\nUsage:  make <target>\n\n'
	@printf '  %-20s  %s\n' build       "CGO_ENABLED=0 go build ./..."
	@printf '  %-20s  %s\n' bin         "Build the daemon into build/ocu-controld (gitignored)"
	@printf '  %-20s  %s\n' dev-secrets "Generate the dev Storage-JWT signing key (idempotent; never overwrites)"
	@printf '  %-20s  %s\n' test        "go test ./...  (e2e legs loud-skip without OCU_CONTROL_BIN)"
	@printf '  %-20s  %s\n' test-race   "go test -race ./..."
	@printf '  %-20s  %s\n' cover       "Coverage floor ($(COVERAGE_FLOOR)%%) over ./internal/..."
	@printf '  %-20s  %s\n' fmt         "gofmt -l . (fails if any file is unformatted)"
	@printf '  %-20s  %s\n' vet         "go vet ./..."
	@printf '  %-20s  %s\n' staticcheck "staticcheck ./..."
	@printf '  %-20s  %s\n' lint        "golangci-lint run (structural meta-linter, .golangci.yml)"
	@printf '  %-20s  %s\n' deadcode    "deadcode -test ./... — fail on any unreachable function (whole-program)"
	@printf '  %-20s  %s\n' vale        "vale doc-prose gate (banned vocab / AI-slop / AP-13) on tracked .md"
	@printf '  %-20s  %s\n' mutation    "go-mutesting score floor on the pure-logic packages (blocking)"
	@printf '  %-20s  %s\n' spdx        "scripts/check-spdx.sh"
	@printf '  %-20s  %s\n' contract    "scripts/check-contract-identity.sh"
	@printf '  %-20s  %s\n' schema      "ajv compile of every vendored contract schema"
	@printf '  %-20s  %s\n' identity    "scripts/check-doc-identity.sh"
	@printf '  %-20s  %s\n' check       "Full local gate: fmt+vet+staticcheck+lint+deadcode+vale+spdx+contract+identity+test"
	@echo

# ── build ───────────────────────────────────────────────────────────────────

build: ## Build all packages (static, no cgo) — mirrors e2e.yml build step
	CGO_ENABLED=0 go build ./...

bin: ## Build the daemon into build/ocu-controld (gitignored — never the repo root)
	mkdir -p build
	CGO_ENABLED=0 go build -trimpath -o build/ocu-controld ./cmd/ocu-controld

# ── dev-secrets ───────────────────────────────────────────────────────────────
#
# Materialize the local development Storage-JWT signing key so the first-run
# quickstart and the compose default mount source actually boot — the daemon is
# fail-closed on a missing -jwt-signing-key, and deploy/docker-compose.yml
# defaults the mount to ./deploy/dev-secrets/storage-jwt-signing.key, which is
# not in a fresh checkout. The generator targets the DEFAULT eddsa alg and is
# idempotent: a re-run never overwrites an existing key (it prints a notice). The
# whole deploy/dev-secrets/ dir is gitignored so a dev key is never staged.
#
# It runs the key-gen via the build-ignored cmd wrapper (over internal/devsecrets
# — the same code the test exercises) with the explicit-file form, because the
# //go:build ignore tag hides the cmd from package-form `go run ./cmd/devsecrets`.
# This is a DEV key only; production provisions the signing key out of band.

dev-secrets: ## Generate the dev Storage-JWT signing key (idempotent; never overwrites)
	go run cmd/devsecrets/main.go deploy/dev-secrets/storage-jwt-signing.key

# ── test ────────────────────────────────────────────────────────────────────
#
# E2e leg: OCU_CONTROL_BIN must point to the static daemon binary.  Build it
# first with `make bin`, which writes build/ocu-controld (a gitignored dir),
# then export OCU_CONTROL_BIN=$(PWD)/build/ocu-controld.  Building into build/
# keeps the daemon out of the repo root so a local build never litters the tree.
# Without OCU_CONTROL_BIN the Integration|E2E slice loud-skips.

test: ## go test ./... (e2e leg loud-skips without OCU_CONTROL_BIN)
	go test ./...

test-race: ## go test -race ./... — mirrors go.yml race job
	go test -race ./... -timeout 600s

# ── cover ───────────────────────────────────────────────────────────────────
#
# Mirrors go.yml coverage job exactly. The floor is $(COVERAGE_FLOOR)%
# (floor(first-measured)-1, ratcheted up over time). Coverage is measured over
# the PRODUCTION packages only — internal/state/statetest (the shared
# conformance-suite test-support package) is excluded because its t.Fatalf error
# branches never execute on a green pass and would deflate the denominator. Set
# OCU_TEST_DATABASE_URL to exercise the Postgres state leg; without it that leg
# live-skips and its lines read as uncovered (so run the DB leg before trusting
# the number locally, exactly as CI does).

# COVER_PKGS is the production internal packages, statetest excluded.
COVER_PKGS = $(shell go list ./internal/... | grep -v '/statetest')
COVER_COVERPKG = $(shell go list ./internal/... | grep -v '/statetest' | paste -sd, -)

cover: ## Collect coverage over the production internal packages and enforce the floor
	go test -coverpkg=$(COVER_COVERPKG) -coverprofile=cover.out $(COVER_PKGS) -timeout 600s -count=1
	@go tool cover -func=cover.out | awk '/^total:/ {gsub(/%/,"",$$3); t=$$3} \
	  END { \
	    f=$(COVERAGE_FLOOR)+0; \
	    if (t+0 < f) { \
	      printf "FAIL: go internal coverage %.1f%% below floor %.1f%%\n", t, f; exit 1 \
	    } \
	    printf "OK:   go internal coverage %.1f%% >= floor %.1f%%\n", t, f \
	  }'

# ── linters ─────────────────────────────────────────────────────────────────

fmt: ## gofmt -l . — fails if any file is unformatted (mirrors go.yml gofmt job)
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "gofmt found unformatted files:"; \
	  echo "$$unformatted"; \
	  exit 1; \
	fi; \
	echo "gofmt clean"

vet: ## go vet ./... — mirrors go.yml vet job
	go vet ./...

staticcheck: ## staticcheck ./... — pinned to $(STATICCHECK_VERSION), matching CI
	@if ! command -v staticcheck >/dev/null 2>&1; then \
	  echo "staticcheck not found — install with:"; \
	  echo "  go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)"; \
	  exit 1; \
	fi
	staticcheck ./...

lint: ## golangci-lint run — structural meta-linter (.golangci.yml), pinned to $(GOLANGCI_LINT_VERSION)
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
	  echo "golangci-lint not found — install with:"; \
	  echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"; \
	  exit 1; \
	fi
	golangci-lint run --timeout=5m ./...

deadcode: ## deadcode -test ./... — fail on any unreachable function (whole-program), pinned to $(GO_DEADCODE_VERSION)
	@if ! command -v deadcode >/dev/null 2>&1; then \
	  echo "deadcode not found — install with:"; \
	  echo "  go install golang.org/x/tools/cmd/deadcode@$(GO_DEADCODE_VERSION)"; \
	  exit 1; \
	fi
	bash scripts/deadcode-gate.sh

vale: ## vale doc-prose gate (banned vocab / AI-slop / AP-13) on tracked .md, pinned to $(VALE_VERSION)
	@if ! command -v vale >/dev/null 2>&1; then \
	  echo "vale not found — install with:"; \
	  echo "  go install github.com/errata-ai/vale/v3/cmd/vale@$(VALE_VERSION)"; \
	  exit 1; \
	fi
	bash scripts/vale-gate.sh

# ── mutation (slower gate — NOT part of `make check`) ─────────────────────────
#
# Mirrors the mutation.yml CI job: go-mutesting on the pure-logic leaf packages
# (admission, killswitch, quota, registry). Mutation testing measures assertion
# strength — it rewrites covered source and re-runs the suite; a mutant the tests
# still pass on is a line executed but not asserted on, which line coverage cannot
# see. scripts/mutation-floor.sh enforces a per-package score floor and fails
# closed on a no-score run (the anti-gremlins guard). It stays its own slower
# target, deliberately excluded from `make check`. (go-gremlins was retired: it is
# structurally blind on this module's comment-led go.mod.)

mutation: ## go-mutesting score floor on the pure-logic packages (blocking) — pinned to $(GO_MUTESTING_VERSION)
	@if ! command -v go-mutesting >/dev/null 2>&1; then \
	  echo "go-mutesting not found — install with:"; \
	  echo "  go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@$(GO_MUTESTING_VERSION)"; \
	  exit 1; \
	fi
	bash scripts/mutation-floor.sh

# ── checks ───────────────────────────────────────────────────────────────────

spdx: ## Assert SPDX FSL-1.1-Apache-2.0 header on all in-scope source files
	bash scripts/check-spdx.sh

contract: ## Assert vendored contracts are byte-identical to the canon (skips if canon absent)
	bash scripts/check-contract-identity.sh

schema: ## Compile every vendored JSON-Schema contract with ajv; validate the A2 golden
	# -c ajv-formats loads the format vocabulary so format:"date-time" is ASSERTED,
	# not silently ignored — without it the golden validate cannot catch a timestamp
	# format drift in the published artifact.
	npx -p ajv-cli@5.0.0 -p ajv-formats@3.0.1 ajv compile --spec=draft2020 --strict=false -c ajv-formats \
	  -s contracts/control/control-rpc.schema.json \
	  -s contracts/exec/exec-channel.schema.json \
	  -s contracts/storage/mount-config.schema.json \
	  -s contracts/mcp/mcp-key-set.schema.json
	# The golden is pinned byte-for-byte to WriteKeySet's output by
	# TestWriteKeySetMatchesGolden, so validating it against the vendored canon
	# schema proves the published A2 artifact conforms to the frozen wire —
	# INCLUDING the RFC3339 date-time formats, now that ajv-formats is loaded.
	npx -p ajv-cli@5.0.0 -p ajv-formats@3.0.1 ajv validate --spec=draft2020 --strict=false -c ajv-formats \
	  -s contracts/mcp/mcp-key-set.schema.json \
	  -d internal/mcpkeyset/testdata/mcp-key-set.golden.json

identity: ## Assert no retired maintainer address in tracked files
	bash scripts/check-doc-identity.sh

seccomp: ## Assert the embedded Docker seccomp profile matches its pinned digest
	bash scripts/check-seccomp-pin.sh

# ── check (one-command pre-push gate) ────────────────────────────────────────
#
# Runs every gate that CI runs on a PR, in dependency order.
# Notable exclusions (because they need external services or elevated perms):
#   - e2e binary slice (needs OCU_CONTROL_BIN)
#   - gitleaks / trufflehog / semgrep / trivy (CI-side tools)
# Those exclusions match CI's own gating model: the plain `test` job also
# loud-skips the gated legs.

check: fmt vet staticcheck lint deadcode vale spdx contract schema identity seccomp test ## Full local gate (pre-push)
