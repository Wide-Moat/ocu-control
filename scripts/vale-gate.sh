#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# GATE 2 (QUAL-02): the documentation-prose gate. It runs vale against the
# Architecture style — a banlist of marketing adjectives, AI-slop preamble
# phrases, and the AP-13 data-class-picks-substrate anti-pattern — over the
# tracked Markdown. The slop-scanner CLASS was DROPPED, not replaced 1:1: no
# vetted Node-free ML-slop detector exists, and dropping in a substitute CLI
# would be fake-green. A deterministic prose banlist is the honest gate instead.
#
# Two tiers, mirroring how canon applies fail_on_error only to its architecture
# tree (the SEMANTICS are carried; the file list is this repo's own):
#
#   ERROR  (blocking): the canon-critical, operator-facing docs — README,
#          CONSTITUTION, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG, and
#          the whole docs/ architecture tree. A finding here fails the gate.
#   WARNING (surfaced, non-blocking): the auxiliary docs — CLAUDE.md (agent
#          instructions), the PR template, examples/, and in-tree component
#          READMEs. Drift is printed but does not fail the build.
#
# Like the dead-code gate, this gates on FINDINGS, not on vale's exit status:
# vale's exit code is configurable and we drive the pass/fail decision from the
# parsed result so a tool quirk can never silently pass a dirty tree. The
# .vale.ini and the Architecture style are vendored BYTE-IDENTICAL from canon
# (one banlist across the fleet); do not edit them here — a banlist change lands
# in canon first.
set -euo pipefail

if ! command -v vale >/dev/null 2>&1; then
  echo "::error::vale not found on PATH"
  echo "  Install the pinned version (same go-install pin model as deadcode/go-mutesting):"
  echo "    go install github.com/errata-ai/vale/v3/cmd/vale@v3.15.1"
  echo "  and ensure \$(go env GOPATH)/bin is on PATH."
  exit 1
fi

# The canon-critical, blocking set. These hold the banned-vocab line.
error_docs=(
  README.md
  CONSTITUTION.md
  CONTRIBUTING.md
  SECURITY.md
  CODE_OF_CONDUCT.md
  CHANGELOG.md
)
# Every architecture doc under docs/ is blocking too.
while IFS= read -r f; do error_docs+=("$f"); done < <(git ls-files 'docs/*.md')

# The auxiliary set: everything else tracked, surfaced as a warning only. We
# derive it as (all tracked .md) MINUS (the blocking set) so a new auxiliary doc
# is covered automatically and can never silently escape the gate entirely.
mapfile -t all_md < <(git ls-files '*.md')
declare -A is_error=()
for f in "${error_docs[@]}"; do is_error["$f"]=1; done
warn_docs=()
for f in "${all_md[@]}"; do
  [ -n "${is_error[$f]:-}" ] || warn_docs+=("$f")
done

fail=0

# (1) Blocking tier: any vale alert at MinAlertLevel (warning, per .vale.ini) on
# these docs fails the gate. We force the decision off the parsed count, not the
# exit code: `--output line` prints one line per alert, so a non-empty result is
# a finding regardless of vale's own exit status.
if [ "${#error_docs[@]}" -gt 0 ]; then
  echo "vale (error tier — canon-critical docs):"
  err_out="$(vale --output line "${error_docs[@]}" 2>&1 || true)"
  if [ -n "$err_out" ]; then
    echo "$err_out"
    echo "::error::vale found prose findings in a canon-critical doc (blocking)"
    echo "  Fix the prose — state the specific property, not the adjective. The"
    echo "  banlist is vendored byte-identical from canon; a banlist change lands"
    echo "  in canon first, never by editing .vale/ here to suppress a finding."
    fail=1
  else
    echo "  OK: 0 findings in ${#error_docs[@]} canon-critical docs"
  fi
fi

# (2) Warning tier: surfaced, never blocking. Drift is visible without gating CI.
if [ "${#warn_docs[@]}" -gt 0 ]; then
  echo "vale (warning tier — auxiliary docs, non-blocking):"
  warn_out="$(vale --output line "${warn_docs[@]}" 2>&1 || true)"
  if [ -n "$warn_out" ]; then
    echo "$warn_out"
    echo "  (auxiliary docs — surfaced, not blocking)"
  else
    echo "  OK: 0 findings in ${#warn_docs[@]} auxiliary docs"
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::vale doc-prose gate failed (a canon-critical doc has a prose finding)"
  exit 1
fi
echo "vale: canon-critical docs are prose-clean"
