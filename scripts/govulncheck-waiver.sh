#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# GATE (SUPPLY-03): the govulncheck waiver gate. It runs govulncheck in JSON
# mode and fails CI on any reachable vulnerability that is NOT on the explicit
# waiver list. The waiver covers five docker/docker@v28.5.2 advisories that have
# no upstream fix (Fixed-in = N/A): the Docker Engine SDK is a build-time
# dependency of the RuntimeProvider, reached via Materialize -> docker-SDK, and
# the project tracks no alternative SDK at this version. Each waived ID is listed
# with its tracking issue and an expiry date; see the WAIVED table below.
#
# Three structural rules carry this gate (a waiver that only suppresses is a
# silent hole an auditor opens first):
#
#   1. FAIL on any reachable finding whose OSV ID is NOT waived. govulncheck
#      reports a finding as reachable when its trace carries a called function
#      (not a bare import); the gate keys on that, never on govulncheck's exit
#      code, so a new docker (or any) advisory that becomes reachable turns this
#      RED rather than slipping under the waiver.
#   2. ANTI-STALE: FAIL when a waived ID is NO LONGER reported. A waived advisory
#      vanishing from the scan means upstream shipped a fix (or the reachable
#      path was removed) — the waiver is now dead weight. The gate goes RED and
#      tells the operator to drop the ID from WAIVED and bump docker, so a waiver
#      cannot outlive the condition that justified it.
#   3. EXPIRY: the waiver carries a review-by date. Past it, the gate goes RED
#      regardless of findings, forcing a fresh reachability + Fixed-in review
#      rather than letting a one-time judgement ride forever.
#
# A run that produces no parseable JSON fails CLOSED — absence of a result is
# never a pass (mirrors scripts/mutation-floor.sh).
#
# Issue: https://github.com/Wide-Moat/ocu-control/issues/6
set -euo pipefail

# --- waiver table -----------------------------------------------------------
# OSV ID -> one-line rationale. All five are docker/docker@v28.5.2, Fixed-in=N/A,
# reachable from RuntimeProvider Materialize -> docker-SDK. Review the set on or
# before WAIVER_REVIEW_BY; re-confirm each is still Fixed-in=N/A and still the
# only path, or remove it.
declare -A WAIVED=(
  [GO-2026-4883]="docker/docker@v28.5.2, Fixed-in=N/A, RuntimeProvider->docker-SDK"
  [GO-2026-4887]="docker/docker@v28.5.2, Fixed-in=N/A, RuntimeProvider->docker-SDK"
  [GO-2026-5617]="docker/docker@v28.5.2, Fixed-in=N/A, RuntimeProvider->docker-SDK"
  [GO-2026-5668]="docker/docker@v28.5.2, Fixed-in=N/A, RuntimeProvider->docker-SDK"
  [GO-2026-5746]="docker/docker@v28.5.2, Fixed-in=N/A, RuntimeProvider->docker-SDK"
)

# Review-by date (YYYY-MM-DD). Past this the gate fails closed and the waiver set
# must be re-reviewed. 90 days from the 2026-06-27 firsthand triage.
WAIVER_REVIEW_BY="2026-09-27"

# --- input ------------------------------------------------------------------
# Accept a pre-captured JSON stream as $1 (used by the red-probe), else run the
# pinned govulncheck. JSON mode is a stream of objects; -C "" pins module mode.
if [[ $# -ge 1 && -f "$1" ]]; then
  JSON="$(cat "$1")"
else
  if ! command -v govulncheck >/dev/null 2>&1; then
    echo "::error::govulncheck not found on PATH"
    echo "  Install the pinned version:"
    echo "    go install golang.org/x/vuln/cmd/govulncheck@v1.3.0"
    exit 1
  fi
  # govulncheck exits non-zero when it finds reachable vulns; we evaluate the
  # JSON ourselves, so do not let its exit code abort the capture.
  #
  # The scan fetches the Go vulnerability database over the network (vuln.go.dev);
  # an unbounded fetch can stall indefinitely (observed: a ~30-minute CI hang that
  # blocked merge). Bound each attempt with `timeout` and retry with backoff so a
  # transient network stall recovers rather than hanging. A `timeout`-killed run
  # exits non-zero and emits no usable JSON, so a hang flows into the empty-output
  # fail-closed gate below — hung => FAIL (then retry), never hung => skip => green.
  # The exit code is intentionally not consulted here (govulncheck exits non-zero
  # on findings too); the JSON-or-empty result is the only signal.
  #
  # SIGNAL DELIVERY: plain `timeout 60` sends SIGTERM, which a process wedged in an
  # uninterruptible network wait (govulncheck's child go-process blocked on the
  # vuln.go.dev fetch) can ignore — `timeout` then waits forever for a SIGTERM that
  # never lands, so the per-attempt bound silently does nothing and the JOB backstop
  # kills it at 5min as CANCELLED (observed: no "attempt 1/3 retrying" warning ever
  # printed, proving attempt 1 never returned). `--kill-after=10` escalates to
  # SIGKILL (uninterruptible, cannot be ignored) 10s after the SIGTERM deadline, so
  # a wedged scan is guaranteed dead at ~70s and the retry loop actually advances.
  #
  # TIMEOUT BUDGET (must finish INSIDE the job's timeout-minutes:5 = 300s backstop):
  # 3 attempts × (60s SIGTERM + 10s SIGKILL grace) + (5s+10s) inter-attempt backoff
  # = 225s worst case, a 75s margin under 300s. The script always reaches its
  # fail-closed branch on its own and emits a deterministic red, never a job-kill
  # CANCELLED. Bumping GOVULNCHECK_TIMEOUT above ~80 reintroduces the conflict —
  # keep 3×(T+10) + 15 < the job backstop.
  SCAN_TIMEOUT="${GOVULNCHECK_TIMEOUT:-60}"
  JSON=""
  for attempt in 1 2 3; do
    JSON="$(timeout --kill-after=10 -s TERM "${SCAN_TIMEOUT}" govulncheck -format json ./... 2>/dev/null || true)"
    if [[ -n "${JSON//[$'\t\r\n ']/}" ]]; then
      break
    fi
    # Backoff only BETWEEN attempts, never after the last (a trailing sleep just
    # burns budget toward the job backstop with no retry to follow).
    if (( attempt < 3 )); then
      echo "::warning::govulncheck attempt ${attempt}/3 produced no JSON (vuln.go.dev fetch stalled or timed out after ${SCAN_TIMEOUT}s); retrying"
      sleep $(( attempt * 5 ))
    fi
  done
  if [[ -z "${JSON//[$'\t\r\n ']/}" ]]; then
    # All retries exhausted with no JSON. Name the likely cause so the next run's
    # log distinguishes a transient stall (retry will eventually win) from a hard
    # egress block to vuln.go.dev (the runner cannot reach the DB at all → this is
    # a real, correct fail-closed, not a flake — the scan genuinely cannot run).
    echo "::error::govulncheck produced no JSON after 3 bounded attempts — the vuln.go.dev DB fetch did not complete. If the runner has no egress to vuln.go.dev, the scan cannot run and this fail-closed is correct; investigate runner egress or switch to an offline DB (GOVULNDB)."
  fi
fi

if [[ -z "${JSON//[$'\t\r\n ']/}" ]]; then
  echo "::error::govulncheck produced no JSON output — failing closed"
  echo "  An empty scan is never a pass; investigate the toolchain before merging."
  exit 1
fi

# --- expiry check -----------------------------------------------------------
# Compare lexically on YYYY-MM-DD; `date -I` is the run date.
TODAY="$(date -I)"
if [[ "$TODAY" > "$WAIVER_REVIEW_BY" ]]; then
  echo "::error::govulncheck waiver expired (review-by ${WAIVER_REVIEW_BY}, today ${TODAY})"
  echo "  Re-review each waived ID (still Fixed-in=N/A? still reachable? still"
  echo "  the only SDK?), update WAIVER_REVIEW_BY, and refresh issue #6."
  exit 1
fi

# --- parse reachable findings ----------------------------------------------
# A govulncheck "finding" frame is reachable when its trace carries a called
# function (a frame with a non-null .function). Collect the distinct OSV IDs of
# such findings. jq -s slurps the NDJSON stream into an array.
REACHED="$(printf '%s' "$JSON" | jq -r -s '
  [ .[]
    | select(.finding != null)
    | .finding
    | select([.trace[]? | select(.function != null)] | length > 0)
    | .osv
  ] | unique | .[]' 2>/dev/null || true)"

# --- rule 1: fail on any reachable, non-waived finding ----------------------
fail=0
non_waived=()
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  if [[ -z "${WAIVED[$id]+x}" ]]; then
    non_waived+=("$id")
  fi
done <<<"$REACHED"

if (( ${#non_waived[@]} > 0 )); then
  fail=1
  echo "::error::govulncheck: reachable vulnerabilities NOT on the waiver list:"
  for id in "${non_waived[@]}"; do
    echo "    - ${id} (https://pkg.go.dev/vuln/${id})"
  done
  echo "  Triage each: bump the dependency if a fix exists, else add to WAIVED"
  echo "  with a tracking issue + Fixed-in=N/A + reachability rationale."
fi

# --- rule 2: anti-stale — fail on any waived ID no longer reported -----------
declare -A REACHED_SET=()
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  REACHED_SET[$id]=1
done <<<"$REACHED"

stale=()
for id in "${!WAIVED[@]}"; do
  if [[ -z "${REACHED_SET[$id]+x}" ]]; then
    stale+=("$id")
  fi
done

if (( ${#stale[@]} > 0 )); then
  fail=1
  echo "::error::govulncheck: waived IDs no longer reachable (upstream fix likely landed):"
  for id in "${stale[@]}"; do
    echo "    - ${id} — remove from WAIVED and bump docker/docker to the fixed version"
  done
  echo "  A waiver must not outlive the condition that justified it."
fi

if (( fail == 0 )); then
  echo "govulncheck waiver gate: PASS"
  echo "  ${#WAIVED[@]} waived advisories all still reachable + Fixed-in=N/A; no"
  echo "  non-waived reachable findings; waiver valid until ${WAIVER_REVIEW_BY}."
fi

exit "$fail"
