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
# A PACKAGE-level reachable finding: the gate runs at -scan-level package, where
# govulncheck emits a single-frame trace with a .package but NO .function (per the
# v1.3.0 Finding doc). The gate's reachability test must treat such a frame as
# reachable too — this fixture proves the package-level arm is not decorative.
package_finding() {
  jq -cn --arg id "$1" \
    '{finding: {osv: $id, trace: [{module: "github.com/docker/docker", package: "github.com/docker/docker/client"}]}}'
}
# A MODULE-ONLY finding: what binary mode emits when the scanned binary is stripped
# (-s -w) — the trace frame carries only .module, no .function and no .package. The
# strip-guard must treat findings that are ALL module-only as a fail-open hazard
# (reachability unresolvable) and fail closed, not silently pass.
module_only_finding() {
  jq -cn --arg id "$1" \
    '{finding: {osv: $id, trace: [{module: "github.com/docker/docker"}]}}'
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

# ── Skeptic E: a PACKAGE-level non-waived finding must go RED ──
# Proves the -scan-level package reachability arm (.package, no .function) is real:
# the all-waived control stays green, but adding a non-waived PACKAGE-level finding
# must still fire. If the gate only recognised .function reachability, this stranger
# would be seen as unreachable and slip through — green — which is the exact gap the
# scan-level switch would have opened.
{ all_waived_stream; package_finding "GO-2026-9999"; } >"$TMP/e.json"
if "$GATE" "$TMP/e.json" >/dev/null 2>&1; then
  echo "::error::Skeptic E — gate PASSED with a non-waived PACKAGE-level finding (GO-2026-9999); the package-scan reachability arm is unguarded"
  exit 1
fi
echo "ok: Skeptic E — a non-waived package-level finding fires RED (scan-level package arm)"

# ── Skeptic F: a stripped binary (findings present, ALL module-only) must go RED ──
# Binary mode against a stripped binary (-s -w) emits findings whose only trace
# frame is .module (no .function/.package) — reachability is unresolvable. Such a
# stream MUST fail closed. The strip-guard fires first with the correct diagnosis
# ("binary is stripped"); anti-stale is a defense-in-depth backstop (the waived IDs
# also read as unresolved). Both are correct — the test asserts the stream is RED,
# the strip-guard's value is the ACCURATE diagnosis (vs anti-stale's misleading
# "upstream fix landed") AND catching a NON-waived module-only finding that rule 1
# would otherwise miss when reachability is empty. NOTE: this is not isolated to
# the strip-guard alone (anti-stale co-fires on the waived-only stream); the
# guard's unique contribution is the diagnosis + the non-waived-in-stripped case.
{ for id in "${WAIVED_IDS[@]}"; do module_only_finding "$id"; done; } >"$TMP/f.json"
if "$GATE" "$TMP/f.json" >/dev/null 2>&1; then
  echo "::error::Skeptic F — gate PASSED on an all-module-only stream (stripped binary); fail-open on an unresolvable scan"
  exit 1
fi
echo "ok: Skeptic F — an all-module-only (stripped-binary) stream fires RED"

echo "govulncheck-waiver-redprobe: non-waived RED, anti-stale RED, fail-closed RED, control GREEN, package-level RED, strip-guard RED all proven; tree clean"
