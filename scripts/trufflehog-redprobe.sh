#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the trufflehog half of the secrets gate.
#
# The failure this guards against is not "trufflehog is missing" -- it is a gate that
# runs and finds nothing because its scope was narrowed until it covered nothing. The
# exclude list is the obvious way that happens: one over-broad entry (say `*.go` or a
# bare `.`) silently removes the entire tree from the scan while the job still goes
# green, and a green secrets job is exactly what an auditor reads as "no secrets".
#
# So this asserts NAMED attribution, not a finding count: it plants a credential in a
# known file and requires trufflehog to report THAT PATH. A count-based check would be
# satisfied by any pre-existing finding elsewhere while the planted one went unseen --
# the gate would "fire" and still be blind to the thing under test.
set -euo pipefail

if ! command -v trufflehog >/dev/null 2>&1; then
  echo "::error::trufflehog not found on PATH; the secrets red-probe cannot run (fail-closed)"
  exit 1
fi

probe_file="zz_trufflehog_redprobe.txt"
cleanup() { rm -f "$probe_file"; }
trap cleanup EXIT

# A structurally valid but entirely fake AWS key pair. It authenticates nothing; the
# scan runs with --no-verification (as CI does), so detection is by shape, and no
# network call is made against it. Assembled at runtime so the literal never appears
# verbatim in a committed file -- otherwise the tree scan would flag this script and
# need an exclude entry, and that entry would also hide the planted match, which is
# the precise way a probe is neutered into agreeing with itself.
#
# The canonical AWS documentation pair (AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI...KEY) is
# deliberately NOT used: scanners allowlist it as a known placeholder, so a probe built
# on it reports nothing and would be read as "the gate is broken" when the gate is
# fine. The same trap is recorded in scripts/gitleaks-redprobe.sh.
akid="AKIA$(printf 'QYLPZ4X7NBVCD2WE')"
secret="wJalrXUtnFEMIK7MDENGbPxRfi$(printf 'CYzR8h2NqLpX4T')"
{
  printf 'aws_access_key_id = %s\n' "$akid"
  printf 'aws_secret_access_key = %s\n' "$secret"
} >"$probe_file"

# CI runs trufflehog through the action, which mounts the repo at /tmp and addresses
# the exclude file there. Locally the same file is repo-root relative; the scanned
# scope is identical either way.
exclude_arg=()
if [ -f .trufflehog-exclude.txt ]; then
  exclude_arg=(--exclude-paths .trufflehog-exclude.txt)
fi

report="$(mktemp)"
trap 'cleanup; rm -f "$report"' EXIT

# trufflehog exits non-zero only with --fail; ask for JSON and judge the CONTENT, so
# the assertion is about what was found and where, not about an exit code.
trufflehog filesystem . --no-verification --json "${exclude_arg[@]}" >"$report" 2>/dev/null || true

if ! grep -q "$probe_file" "$report"; then
  echo "::error::trufflehog did not report the planted credential in ${probe_file}. The secrets scan is not covering the tree -- check .trufflehog-exclude.txt for an over-broad entry, and the action's path/version inputs."
  exit 1
fi
echo "ok: gate is RED on the planted credential, and names ${probe_file}"

cleanup
trap 'rm -f "$report"' EXIT
trufflehog filesystem . --no-verification --json "${exclude_arg[@]}" >"$report" 2>/dev/null || true
if grep -q "$probe_file" "$report"; then
  echo "::error::trufflehog still reports ${probe_file} after removal; the probe file was not cleaned up"
  exit 1
fi
echo "ok: clean after removing the probe"

echo "trufflehog-redprobe: gate fires RED on a planted credential and names the planted file"
