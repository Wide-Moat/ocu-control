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

probe_dir="zz_semgrep_redprobe"
probe_file="${probe_dir}/probe.go"
report="$(mktemp)"
cleanup() { rm -rf "$probe_dir"; rm -f "$report"; }
trap cleanup EXIT

# A scanner container fed a git WORKTREE sees `.git` as a FILE pointing at
# .git/worktrees/<name>, which does not resolve inside the container; a git-mode scan
# then reads nothing and reports "0 findings, exit 0". On a clean tree that zero is
# indistinguishable from success, so refuse to run rather than produce it. CI checks
# out an ordinary clone, so this only fires during local debugging -- which is exactly
# when a false green would be believed.
if [ -e .git ] && [ ! -d .git ]; then
  echo "::error::this tree is a git worktree (.git is a file). A scanner cannot resolve it from inside a container and would report zero findings. Run the probe from an ordinary clone."
  exit 1
fi

# THE PLANTED DEFECT IS THIS REPO'S OWN IDIOM, NOT THE RULE'S TEXTBOOK SHAPE.
# A rule can match `md5.Sum(x)` and miss the streaming `h := md5.New(); h.Write(...)`
# form -- and a probe written in the shape the rule documents proves only that the
# rule fires on its own documentation. So the plant is a copy of the real hash
# construction in internal/cred/signer.go (deriveJTI) with sha256 swapped for md5:
# the exact regression a careless edit there would produce, written the way this
# codebase actually writes it.
#
# It goes in its own directory and package so it never collides with the real one.
mkdir -p "$probe_dir"
cat >"$probe_file" <<'GO'
package probe

import (
	"crypto/md5"
	"encoding/base64"
	"time"
)

// deriveJTI mirrors internal/cred/signer.go's real construction, with the hash
// weakened. The shape -- streaming Writes into a hash.Hash, then Sum(nil) -- is this
// repository's idiom, which is the point: the probe must exercise the code shape the
// gate will actually meet.
func deriveJTI(sessionKey, filesystemID string, at time.Time) string {
	h := md5.New()
	h.Write([]byte(sessionKey))
	h.Write([]byte{0})
	h.Write([]byte(filesystemID))
	h.Write([]byte{0})
	var nano [8]byte
	n := at.UnixNano()
	for i := 0; i < 8; i++ {
		nano[i] = byte(n >> (8 * i) & 0xff)
	}
	h.Write(nano[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
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
hits = [r for r in data.get("results", []) if planted in r.get("path", "")]
if not hits:
    raise SystemExit(1)
print(f"planted file reported by rule(s): {sorted({h.get('check_id','?') for h in hits})}")
PY
then
  echo "::error::semgrep did not report the planted weak-hash use in ${probe_file}. Either the SAST gate has no effective rules (check SEMGREP_RULES and that each ruleset still resolves), or its Go rules do not match this repository's hashing idiom -- which would mean the gate is blind to the real regression, not that the probe is wrong."
  exit 1
fi
echo "ok: gate is RED on a planted finding, and names ${probe_file}"

echo "semgrep-redprobe: gate fires RED on a planted finding and names the planted file"
