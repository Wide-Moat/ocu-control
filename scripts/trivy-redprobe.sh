#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the SCA gate.
#
# An SCA gate has two quiet ways to guard nothing, and neither shows up as a failure:
# a severity floor set above what the ecosystem actually produces (a CRITICAL-only
# gate on a Go module is near-vacuous -- the advisories are overwhelmingly HIGH), and
# a .trivyignore that grows until it covers the findings instead of documenting them.
# Both leave a green job that an auditor reads as "no vulnerable dependencies".
#
# So this plants a dependency with known CRITICAL/HIGH advisories and requires trivy
# to report THAT FILE. Naming the planted target is the point: a count-based assertion
# would be satisfied by any pre-existing finding while the planted one sat unseen,
# which is the exact failure -- the gate "fires" and is still blind to what was added.
#
# The probe scans with the SAME severity floor and ignore file as CI, so it is a proof
# about the configured gate, not about trivy in general.
set -euo pipefail

if ! command -v trivy >/dev/null 2>&1; then
  echo "::error::trivy not found on PATH; the SCA red-probe cannot run (fail-closed)"
  exit 1
fi

probe_file="requirements.txt"
if [ -e "$probe_file" ]; then
  echo "::error::${probe_file} already exists; the probe would overwrite a real file. Rename the probe target."
  exit 1
fi

report="$(mktemp)"
cleanup() { rm -f "$probe_file" "$report"; }
trap cleanup EXIT

# A long-EOL Python package with many CRITICAL/HIGH advisories. The language is
# deliberately NOT Go: planting a vulnerable Go module would need a matching go.sum
# entry and a network fetch, which makes the probe fragile for no gain. What is under
# test is whether the CONFIGURED gate reports a vulnerable dependency it can see, and
# trivy's filesystem scan covers every manifest kind in the tree -- so a Python
# manifest exercises the same gate the Go modules flow through.
printf 'Django==1.2\n' >"$probe_file"

ignore_arg=()
if [ -f .trivyignore ]; then
  ignore_arg=(--ignorefile .trivyignore)
fi

# Judge the report CONTENT, not the exit code: the assertion is that the planted file
# is named with at least one finding at the gate's own severity floor.
trivy fs --severity CRITICAL,HIGH --format json --output "$report" \
  "${ignore_arg[@]}" --scanners vuln . >/dev/null 2>&1 || true

if ! python3 - "$report" "$probe_file" <<'PY'
import json, sys
report, planted = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(report))
except Exception as exc:  # noqa: BLE001 - any unreadable report is a failed probe
    print(f"could not read the trivy report: {exc}")
    raise SystemExit(1)
for result in data.get("Results") or []:
    if result.get("Target", "").endswith(planted) and (result.get("Vulnerabilities") or []):
        n = len(result["Vulnerabilities"])
        print(f"planted target reported with {n} CRITICAL/HIGH findings")
        raise SystemExit(0)
raise SystemExit(1)
PY
then
  echo "::error::trivy did not report CRITICAL/HIGH findings for the planted ${probe_file}. The SCA gate is not blocking on vulnerable dependencies -- check the severity floor and .trivyignore."
  exit 1
fi
echo "ok: gate is RED on a planted vulnerable dependency, and names ${probe_file}"

rm -f "$probe_file"
trivy fs --severity CRITICAL,HIGH --format json --output "$report" \
  "${ignore_arg[@]}" --scanners vuln . >/dev/null 2>&1 || true
if python3 -c "
import json,sys
d=json.load(open('$report'))
print(sum(len(r.get('Vulnerabilities') or []) for r in (d.get('Results') or [])))
" | grep -qv '^0$'; then
  echo "::warning::the tree itself reports CRITICAL/HIGH findings after removing the probe; the SCA gate is red for real reasons, which is a separate matter from this proof"
fi
echo "trivy-redprobe: gate fires RED on a planted vulnerable dependency and names the planted file"
