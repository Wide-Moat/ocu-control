#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the govulncheck waiver gate. A waiver gate that
# never fires would silence every advisory — the worst possible outcome for a
# supply-chain control. This proves each of the gate's four RED directions fires,
# feeding the gate synthetic govulncheck JSON (the gate accepts a captured stream
# as $1), so the proof is hermetic — no real scan, nothing left on disk.
#
#   Skeptic A (non-waived reachable -> RED): a finding whose OSV ID is NOT on the
#     waiver, reachable (a called function in its trace), must fail the gate.
#   Skeptic B (anti-stale -> RED): a stream where a WAIVED ID is absent (upstream
#     fix landed) must fail the gate — the load-bearing audit-clean property.
#   Skeptic C (empty input -> RED): a blank stream must fail closed — absence of a
#     result is never a pass.
#   Skeptic D (all-waived-present -> GREEN): the control case — every waived ID
#     present and reachable, no stranger — must PASS, proving the gate is not a
#     constant-RED stub that "passes" the others vacuously.
#
# Issue: https://github.com/Wide-Moat/ocu-control/issues/6
set -euo pipefail

GATE="$(dirname "$0")/govulncheck-waiver.sh"
if [[ ! -x "$GATE" ]]; then
  chmod +x "$GATE" 2>/dev/null || true
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "::notice::jq not installed — skipping the govulncheck waiver red-probe (advisory parity for local dev)"
  exit 0
fi

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# A reachable govulncheck finding frame for a given OSV id (a called function in
# the trace is what makes it reachable). One JSON object per line (NDJSON).
finding() {
  jq -cn --arg id "$1" \
    '{finding: {osv: $id, trace: [{module: "github.com/docker/docker", function: "NetworkCreate"}]}}'
}
# The five real waived IDs.
WAIVED_IDS=(GO-2026-4883 GO-2026-4887 GO-2026-5617 GO-2026-5668 GO-2026-5746)

all_waived_stream() {
  for id in "${WAIVED_IDS[@]}"; do finding "$id"; done
}

# ── Skeptic A: a non-waived reachable finding must go RED ──
{ all_waived_stream; finding "GO-2026-9999"; } >"$TMP/a.json"
if "$GATE" "$TMP/a.json" >/dev/null 2>&1; then
  echo "::error::Skeptic A — gate PASSED with a non-waived reachable finding (GO-2026-9999); it guards nothing"
  exit 1
fi
echo "ok: Skeptic A — a non-waived reachable finding fires RED"

# ── Skeptic B: a missing waived ID (upstream fix landed) must go RED ──
# Drop one waived ID from the stream; anti-stale must catch it.
{ for id in "${WAIVED_IDS[@]:1}"; do finding "$id"; done; } >"$TMP/b.json"
if "$GATE" "$TMP/b.json" >/dev/null 2>&1; then
  echo "::error::Skeptic B — gate PASSED with a waived ID absent; ANTI-STALE is unguarded (the audit-clean property)"
  exit 1
fi
echo "ok: Skeptic B — a vanished waived ID fires RED (anti-stale)"

# ── Skeptic C: an empty stream must fail closed ──
: >"$TMP/c.json"
if "$GATE" "$TMP/c.json" >/dev/null 2>&1; then
  echo "::error::Skeptic C — gate PASSED on empty input; it does not fail closed"
  exit 1
fi
echo "ok: Skeptic C — an empty scan fires RED (fail closed)"

# ── Skeptic D: the control case — all waived present, no stranger — must PASS ──
all_waived_stream >"$TMP/d.json"
if ! "$GATE" "$TMP/d.json" >/dev/null 2>&1; then
  echo "::error::Skeptic D — gate FAILED the all-waived-present control case; it is a constant-RED stub, not a real gate"
  "$GATE" "$TMP/d.json" || true
  exit 1
fi
echo "ok: Skeptic D — all-waived-present control case PASSES (the gate is not constant-RED)"

echo "govulncheck-waiver-redprobe: non-waived RED, anti-stale RED, fail-closed RED, control GREEN all proven; tree clean"
