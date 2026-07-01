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
  # MODE: `-mode binary`, NOT the default source scan. Binary mode reads the
  # symbol table of an ALREADY-BUILT binary (runBinary ->
  # ExtractPackagesAndSymbols -> vulncheck.Binary in govulncheck v1.3.0) — no
  # package loading, no SSA — so it finishes in ~1s, is deterministic, and needs
  # no `go` toolchain at scan time. Same vuln.go.dev DB; the only coverage delta
  # is GOOS/GOARCH-bound (the one built platform) and a superset of
  # symbol-present-but-unreachable findings — both safe for a single-platform CI
  # gate. (The 2026-06/07 "CI hang" was once blamed on the source scan's
  # toolchain fork; the proven root cause was this script's own quadratic
  # non-emptiness check — see the O(n) note below. Binary mode stays on its own
  # merits: speed, determinism, no toolchain at scan time.)
  #
  # INVOCATION: `-mode binary` takes a positional path to ONE built binary, NOT
  # `./...`. The binary path is OCU_GATE_BINARY, an UNSTRIPPED controld the
  # govulncheck CI job builds (`go build -trimpath`, no `-s -w`). The JSON shape is
  # identical to source mode (the same NDJSON {"finding":{...}} Frame stream), so
  # the waiver evaluation, the reachability filter, anti-stale, and expiry are all
  # unchanged. `-mode` is the v1.3.0 flag (internal/scan/flags.go:43 supports
  # 'source'/'binary'/'extract'); re-check the flag spelling on any govulncheck bump.
  #
  # The scan runs under setsid + a bounded timeout as a seatbelt (the bound makes
  # any future scanner-side regression a deterministic honest-red rather than a
  # stuck job) with stdout to a FILE.
  if [[ -z "${OCU_GATE_BINARY:-}" || ! -f "${OCU_GATE_BINARY:-/nonexistent}" ]]; then
    echo "::error::OCU_GATE_BINARY is unset or not a file — binary-mode govulncheck needs an unstripped built binary to scan; failing closed"
    echo "  The govulncheck CI job must build an UNSTRIPPED controld (go build -trimpath, no -s -w) and export OCU_GATE_BINARY=<path>."
    exit 1
  fi
  SCAN_TIMEOUT="${GOVULNCHECK_TIMEOUT:-60}"
  JSON=""
  for attempt in 1 2 3; do
    GVJSON="$(mktemp)"
    setsid timeout -s KILL --kill-after=10 "${SCAN_TIMEOUT}" \
      govulncheck -mode binary -format json "${OCU_GATE_BINARY}" >"${GVJSON}" 2>/dev/null </dev/null || true
    JSON="$(cat "${GVJSON}")"
    rm -f "${GVJSON}"
    # Non-emptiness = "carries at least one non-whitespace char", tested with a
    # glob MATCH (one left-to-right scan, O(n)). NEVER test this with the
    # ${JSON//[$'\t\r\n ']/} substitution: on the runners' bash that
    # substitution is quadratic over the ~540 KB scan stream and spins the
    # shell for >20 minutes of pure CPU — the original "CI hang" of issue #6
    # in its entirety (the scan, setsid, timeout, and the runner were healthy).
    if [[ "$JSON" == *[![:space:]]* ]]; then
      break
    fi
    # Backoff only BETWEEN attempts, never after the last (a trailing sleep just
    # burns budget toward the job backstop with no retry to follow).
    if (( attempt < 3 )); then
      echo "::warning::govulncheck attempt ${attempt}/3 produced no JSON (scan wedged or timed out after ${SCAN_TIMEOUT}s); retrying"
      sleep $(( attempt * 5 ))
    fi
  done
  # Glob match, not substitution — see the O(n) note above.
  if [[ "$JSON" != *[![:space:]]* ]]; then
    # All retries exhausted with no JSON. Name the likely cause so the next run's
    # log distinguishes a transient stall (retry will eventually win) from a hard
    # egress block to vuln.go.dev (the runner cannot reach the DB at all → this is
    # a real, correct fail-closed, not a flake — the scan genuinely cannot run).
    echo "::error::govulncheck produced no JSON after 3 bounded attempts — the vuln.go.dev DB fetch did not complete. If the runner has no egress to vuln.go.dev, the scan cannot run and this fail-closed is correct; investigate runner egress or switch to an offline DB (GOVULNDB)."
  fi
fi

# Glob match, not substitution — see the O(n) note above.
if [[ "$JSON" != *[![:space:]]* ]]; then
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
# Reachability keys on a trace frame carrying a non-null .function (a called
# symbol) OR a non-null .package (the package is present in the scanned binary's
# symbol table). Binary mode against an UNSTRIPPED binary populates both, so this
# filter is correct here; it also stays correct for a source/package scan (where a
# package-level finding's single frame carries .package, not .function), so the
# gate does not depend on the scan mode. Collect the distinct OSV IDs of reachable
# findings. jq -s slurps the NDJSON stream into an array.
REACHED="$(printf '%s' "$JSON" | jq -r -s '
  [ .[]
    | select(.finding != null)
    | .finding
    | select([.trace[]? | select(.function != null or .package != null)] | length > 0)
    | .osv
  ] | unique | .[]' 2>/dev/null || true)"

# --- strip-guard: a stripped binary is a FAIL-OPEN hole, refuse it --------------
# Binary mode needs symbols. If the scanned binary was built with `-ldflags=-s -w`
# (symtab + DWARF stripped), govulncheck falls back to MODULE granularity: every
# finding's trace then carries only .module — no .function, no .package — so the
# reachability filter above returns ZERO even when findings exist. That would
# silently miss non-waived vulns AND falsely fire anti-stale (every waived ID
# "vanished"). Detect it: findings present but NOT ONE frame carries .function or
# .package across the whole stream => the binary is stripped, the gate cannot
# resolve reachability, fail closed. (Distinct from "no findings at all", which is
# a legitimate clean scan handled by the rules below.)
FINDING_COUNT="$(printf '%s' "$JSON" | jq -s '[ .[] | select(.finding != null) ] | length' 2>/dev/null || echo 0)"
RESOLVABLE_COUNT="$(printf '%s' "$JSON" | jq -s '
  [ .[] | select(.finding != null) | .finding
    | select([.trace[]? | select(.function != null or .package != null)] | length > 0)
  ] | length' 2>/dev/null || echo 0)"
if [[ "${FINDING_COUNT:-0}" -gt 0 && "${RESOLVABLE_COUNT:-0}" -eq 0 ]]; then
  echo "::error::govulncheck binary-mode produced ${FINDING_COUNT} finding(s) but NONE carry a .function or .package frame — the scanned binary is stripped (-s -w), so reachability cannot be resolved. Failing closed."
  echo "  Build the gate's binary WITHOUT -ldflags='-s -w' (default go build keeps symbols); OCU_GATE_BINARY must be unstripped."
  exit 1
fi

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
