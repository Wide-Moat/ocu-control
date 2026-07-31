#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the SAST gate.
#
# The way a SAST gate goes quiet is by losing its rules, not by crashing: a trimmed
# SEMGREP_RULES, a ruleset renamed upstream, or a config that resolves to nothing all
# leave semgrep exiting 0 with an empty findings list. That is indistinguishable from
# a clean codebase in every signal an auditor sees -- the job is green and the Security
# tab is empty.
#
# So this plants a finding the CONFIGURED rulesets are expected to catch and requires
# semgrep to name THAT FILE. Asserting a finding count would not do: a pre-existing
# finding elsewhere would satisfy the count while the planted one went unseen, which
# is exactly the blindness under test.
set -euo pipefail

# The gate's own ruleset list, kept identical to the CI job's SEMGREP_RULES.
RULES="${SEMGREP_RULES:-p/security-audit p/owasp-top-ten p/golang p/github-actions p/secrets}"

probe_file="zz_semgrep_redprobe.go"
report="$(mktemp)"
cleanup() { rm -f "$probe_file" "$report"; }
trap cleanup EXIT

# Weak-hash use: a finding the Go security rules carry, in a file that compiles on its
# own and touches nothing else in the tree.
cat >"$probe_file" <<'GO'
//go:build ignore

package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	sum := md5.Sum([]byte("probe"))
	fmt.Println(sum)
}
GO

# In CI this runs INSIDE the pinned semgrep container, so the binary is on PATH and is
# the same one the gate uses. Locally there is no semgrep, so fall back to the same
# pinned image by digest -- the probe must exercise the pinned scanner, not whatever
# happens to be installed.
run_semgrep() {
  if command -v semgrep >/dev/null 2>&1; then
    # shellcheck disable=SC2086 - RULES is a deliberately word-split list
    semgrep scan --json --quiet $(for r in $RULES; do printf -- '--config=%s ' "$r"; done) . 2>/dev/null
  elif command -v docker >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    docker run --rm -v "$PWD:/src" -w /src \
      semgrep/semgrep:1.144.0@sha256:10301f060aacf84078f9704fb1ba3a321df4ac46b009fd29c1c66880d1db8e77 \
      semgrep scan --json --quiet $(for r in $RULES; do printf -- '--config=%s ' "$r"; done) . 2>/dev/null
  else
    echo "::error::neither semgrep nor docker is available; the SAST red-probe cannot run (fail-closed)" >&2
    exit 1
  fi
}

run_semgrep >"$report" || true

if ! python3 - "$report" "$probe_file" <<'PY'
import json, sys
report, planted = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(report))
except Exception as exc:  # noqa: BLE001 - an unreadable report is a failed probe
    print(f"could not read the semgrep report: {exc}")
    raise SystemExit(1)
hits = [r for r in data.get("results", []) if r.get("path", "").endswith(planted)]
if not hits:
    raise SystemExit(1)
print(f"planted file reported by rule(s): {sorted({h.get('check_id','?') for h in hits})}")
PY
then
  echo "::error::semgrep did not report the planted weak-hash use in ${probe_file}. The SAST gate is running with no effective rules -- check SEMGREP_RULES and that each ruleset still resolves."
  exit 1
fi
echo "ok: gate is RED on a planted finding, and names ${probe_file}"

echo "semgrep-redprobe: gate fires RED on a planted finding and names the planted file"
