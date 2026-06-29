#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# GATE 3 (QUAL-03): the mutation-test score floor. It runs go-mutesting on the
# pure-logic leaf packages and fails CI when any package's mutation score drops
# below its per-package floor — enforcing assertion strength (not just line
# coverage) as a blocking gate.
#
# Two structural rules carry this gate:
#
#   1. Gate on the PARSED score, never on go-mutesting's exit code. go-mutesting
#      uses inverted terminology (PASS = mutant killed = good) and exits 0
#      regardless of score, so keying on $? would pass a suite full of surviving
#      mutants.
#   2. A run that produces NO score fails CLOSED (the anti-gremlins guard). The
#      retired gremlins gate was structurally blind on this module — it mutated
#      nothing and reported a phantom 0%/Not-Covered for every package — so a
#      tool that "passes" by building nothing must be a failure here, not a pass.
#      Absence of a score is never a high score.
#
# Floors are floor(measured), ratcheted UP as suites are hardened (never down).
# Firsthand 2026-06-24 baselines: admission 1.000, killswitch 0.839, quota 0.609,
# registry 0.529. registry has since been HARDENED to 1.000 (its 8 surviving
# mutants killed — the DeriveKey golden/per-field tests and the transient-error
# propagation tests), so its floor is ratcheted to 1.0. quota has since been
# HARDENED to 0.804 — its load-bearing refund-path survivors killed via a
# recording+faulting Store fixture (first-refund-error capture/return, first-not-
# last error identity, RefundConcurrent store-error propagation, and the exact
# refund delta/limit each compensator issues, which the saturating in-memory Store
# otherwise masks) — so its floor is ratcheted 0.6 -> 0.8. The 9 remaining quota
# survivors are equivalent or brittle (negative-delta limit-arg mutants the Store
# never refuses; the unwindStepTimeout const; the unexported empty-Receipt guard
# unreachable through the public API; dayWindow truncation masked by a date-only
# layout on an unwired later-phase function) and are deliberately not chased — a
# low floor is never silently accepted, but neither is a cosmetic one bought with
# brittle over-fitting.
set -euo pipefail

# go-mutesting writes a report.json into the working dir on each run; remove it
# so a local `make mutation` never leaves an untracked artifact behind.
cleanup() { rm -f report.json; }
trap cleanup EXIT

if ! command -v go-mutesting >/dev/null 2>&1; then
  echo "::error::go-mutesting not found on PATH"
  echo "  Install the pinned version (no semver tag exists; the commit IS the pin):"
  echo "    go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@v0.0.0-20251226130216-48d0401f00fb"
  echo "  and ensure \$(go env GOPATH)/bin is on PATH."
  exit 1
fi

declare -A FLOOR=(
  [admission]=1.0
  [killswitch]=0.8
  [quota]=0.8
  [registry]=1.0
)

# --exec-timeout raises go-mutesting's per-mutant test-run window from its 10s
# default. A mutant whose test run does not fail early runs the full suite to
# completion; that slowest exec is timeout-sensitive on a loaded CI runner. The
# admission package is the worked case: it has no loops (Decide is a total
# bounds-check-plus-table-index), so its costliest mutant is a long-but-FINITE
# exec, not an infinite loop. Firsthand wall-time of the admission run (18
# mutants, all killed): ~0.48s/mutant unloaded; 8.68s total under a 16-core CPU
# burn; 14.75s total (worst single compile+test 1.576s) under GOMAXPROCS=1 + a
# 16-core burn — the closest local model of a weak, contended runner. The 2-vCPU
# ubuntu-latest runner under co-tenant load (the sibling coverage/race/staticcheck
# jobs share its cores) cannot be reproduced exactly here, so the exact CI worst
# case is unmeasured; 60s is chosen with the margin on the side of STRICTNESS
# (~37x the measured 1.576s worst). This cannot mask a real gap: a genuine
# survivor is a mutant that is NEVER killed — it reads as survived at 10s, 60s, or
# 600s alike — so a wider window only removes the infra-timeout flake (a
# finite mutant killed locally in 1.6s that the 10s CI window intermittently
# missed), never a true suite gap. The floor is unchanged.
fail=0
for pkg in admission killswitch quota registry; do
  out="$(go-mutesting --exec-timeout=60 "./internal/${pkg}/" 2>&1)"
  score="$(printf '%s\n' "$out" | sed -n -E 's/.*mutation score is ([0-9.]+).*/\1/p')"
  if [ -z "$score" ]; then
    echo "::error::go-mutesting produced no score for ${pkg} (it built nothing — the gremlins-blindness regression class; a no-score run fails closed)"
    fail=1
    continue
  fi
  awk -v s="$score" -v f="${FLOOR[$pkg]}" -v p="$pkg" 'BEGIN{
    if (s+0 < f+0) { printf "::error::%s mutation score %.4f below floor %.2f\n", p, s, f; exit 1 }
    printf "OK: %s mutation score %.4f >= floor %.2f\n", p, s, f
  }' || fail=1
done

if [ "$fail" -ne 0 ]; then
  echo "::error::mutation floor gate failed (a package is below floor or produced no score)"
  exit 1
fi
echo "mutation: all scoped packages meet their floor"
