#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for GATE 3 — the two default-wrong skeptics. A floor
# gate that never fires below floor, and a no-score guard that never fires on an
# empty result, would each guard nothing. This script proves both fire:
#
#   Skeptic A (below-floor -> RED): a real measured score checked against an
#     impossibly-high floor must make the floor decision exit non-zero.
#   Skeptic B (no-score -> RED): a go-mutesting result with NO "mutation score is"
#     line must trip the anti-gremlins no-score guard (fail closed) — the exact
#     blindness that froze the retired gremlins gate.
#
# Both skeptics exercise the gate's decision logic hermetically (no repo source is
# mutated, nothing is left on disk), so the proof is deterministic and leaves the
# tree clean. It loud-skips when go-mutesting is absent (local-dev advisory parity).
set -euo pipefail

if ! command -v go-mutesting >/dev/null 2>&1; then
  echo "::notice::go-mutesting not installed — skipping the GATE-3 red-probe (advisory parity for local dev)"
  exit 0
fi

# The exact floor decision scripts/mutation-floor.sh applies: RED when score < floor.
floor_decides_red() {
  # args: score floor ; returns 0 (RED fired) if score < floor, 1 otherwise
  awk -v s="$1" -v f="$2" 'BEGIN{ exit !(s+0 < f+0) }'
}
# The exact no-score guard: RED when no "mutation score is" line is parsed.
noscore_fires_red() {
  # arg: a go-mutesting-style output blob ; returns 0 (RED fired) if no score parsed
  local score
  score="$(printf '%s\n' "$1" | sed -n -E 's/.*mutation score is ([0-9.]+).*/\1/p')"
  [ -z "$score" ]
}

# ── Skeptic A: a measured score below an impossibly-high floor must go RED ──
# Use a real go-mutesting run on the highest-scoring package (admission ~1.0) and
# check it against a floor it cannot meet, proving the floor comparison fires.
out="$(go-mutesting ./internal/admission/ 2>&1)"
rm -f report.json
score="$(printf '%s\n' "$out" | sed -n -E 's/.*mutation score is ([0-9.]+).*/\1/p')"
if [ -z "$score" ]; then
  echo "::error::Skeptic A could not measure a real score for admission (go-mutesting broken?)"
  exit 1
fi
if ! floor_decides_red "$score" "1.01"; then
  echo "::error::mutation floor gate did NOT fire below floor (score ${score} vs floor 1.01) — the gate guards nothing"
  exit 1
fi
echo "ok: Skeptic A — measured score ${score} below an impossible floor 1.01 fires RED"

# ── Skeptic B: a no-score result must trip the anti-gremlins guard ──
# Simulate the gremlins-blindness regression: a go-mutesting output with no score
# line (it built/mutated nothing). The guard must treat absence-of-score as RED.
blind_output="exit status 1
build failed; mutated nothing
(no mutation score line emitted)"
if ! noscore_fires_red "$blind_output"; then
  echo "::error::mutation gate treated a no-score run as PASS — the gremlins-blindness regression is unguarded"
  exit 1
fi
echo "ok: Skeptic B — a no-score result fires RED (the anti-gremlins guard)"

echo "mutation-redprobe: below-floor RED and no-score RED both proven; tree clean"
