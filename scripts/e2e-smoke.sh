# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Real-binary smoke: assert the composed daemon refuses bad invocations
# BEFORE binding any listener. One committed source of truth so the e2e and
# release workflows assert the SAME load-bearing invariants against the SAME
# binary instead of hand-rolling drifting copies in YAML.
#
# Usage:  bash scripts/e2e-smoke.sh /path/to/ocu-controld
#
# The four checks (each must exit 1 with a stable substring of the typed error
# main.go emits, and never bind a listener):
#   1. a missing required flag is NAMED in the refusal text;
#   2. an unknown -runtime-tier is refused, never silently defaulted;
#   3. an unknown -runtime-provider is refused, never silently defaulted;
#   4. KILL-SWITCH-FIRST: a create presented at startup is refused loudly
#      end-to-end before any listener binds (NFR-SEC-01), and no socket is
#      bound on the refusal.
set -uo pipefail

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "::error::usage: e2e-smoke.sh <path-to-ocu-controld> (executable)"
  exit 2
fi

fail=0

# A scratch socket directory: if any refusal path wrongly bound a listener,
# a stray socket would land here and the final check would catch it.
tmp=$(mktemp -d)
opsock="unix://$tmp/operator.sock"
gwsock="unix://$tmp/gateway.sock"

# A fully-valid argument set EXCEPT the one field each check perturbs. Kept in
# one array so the checks differ only in the deviation under test.
valid_args=(
  -operator-listen "$opsock"
  -gateway-listen "$gwsock"
  -runtime-tier runc
  -runtime-provider docker
  -jwt-signing-key "$tmp/jwt-signing.key"
  -audit-sink "$tmp/audit.ocsf.jsonl"
)

# 1. missing required flag — exit 1, typed error, the first missing flag named.
#    Supply only -runtime-tier so -operator-listen is the first absent required
#    flag and must be the one named.
code=0
out=$("$BIN" -runtime-tier runc 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on a missing required flag, got $code"
  fail=1
fi
echo "$out" | grep -q "required flag missing or invalid" || {
  echo "::error::missing-required-flag error text missing from output"
  fail=1
}
echo "$out" | grep -q -- "-operator-listen" || {
  echo "::error::expected the first missing required flag (-operator-listen) to be named"
  fail=1
}

# 2. unknown runtime tier — refused, never silently defaulted.
code=0
out=$("$BIN" -operator-listen "$opsock" -gateway-listen "$gwsock" \
  -runtime-tier bogus -runtime-provider docker \
  -jwt-signing-key "$tmp/jwt-signing.key" -audit-sink "$tmp/audit.ocsf.jsonl" 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on unknown runtime tier, got $code"
  fail=1
fi
echo "$out" | grep -q "unknown runtime tier" || {
  echo "::error::unknown-runtime-tier sentinel missing from output"
  fail=1
}

# 3. unknown runtime provider — refused, never silently defaulted.
code=0
out=$("$BIN" -operator-listen "$opsock" -gateway-listen "$gwsock" \
  -runtime-tier runc -runtime-provider podman \
  -jwt-signing-key "$tmp/jwt-signing.key" -audit-sink "$tmp/audit.ocsf.jsonl" 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on unknown runtime provider, got $code"
  fail=1
fi
echo "$out" | grep -q "unknown runtime provider" || {
  echo "::error::unknown-runtime-provider sentinel missing from output"
  fail=1
}

# 4. KILL-SWITCH-FIRST — a create presented at startup is refused loudly,
#    naming NFR-SEC-01, before any listener binds; and no socket exists.
code=0
out=$("$BIN" "${valid_args[@]}" -create-on-start 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on a create-before-bind, got $code"
  fail=1
fi
echo "$out" | grep -q "NFR-SEC-01" || {
  echo "::error::the kill-switch-first refusal must name NFR-SEC-01"
  fail=1
}
if ls "$tmp"/*.sock >/dev/null 2>&1; then
  echo "::error::a socket was bound despite the kill-switch-first refusal"
  fail=1
fi

# 4b. The kill-switch-first refusal now flows through the REAL boot + Store
#     path. An explicit empty -state-dsn (the in-memory minimal-shelf default)
#     must refuse identically, documenting the default and confirming the
#     create-on-start path exercises the live boot sequencer, not a stub branch.
code=0
out=$("$BIN" "${valid_args[@]}" -state-dsn "" -create-on-start 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on a create-before-bind with explicit -state-dsn '', got $code"
  fail=1
fi
echo "$out" | grep -q "NFR-SEC-01" || {
  echo "::error::the in-memory-default kill-switch-first refusal must name NFR-SEC-01"
  fail=1
}
if ls "$tmp"/*.sock >/dev/null 2>&1; then
  echo "::error::a socket was bound despite the kill-switch-first refusal (explicit -state-dsn '')"
  fail=1
fi

rm -rf "$tmp"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "real-binary smoke passed: all four pre-bind refusals hold"
