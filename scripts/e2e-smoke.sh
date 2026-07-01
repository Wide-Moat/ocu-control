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
#   4. KILL-SWITCH-FIRST ORDERING: a create presented BEFORE the boot sequencer
#      loads the durable deny posture is refused loudly by the transient
#      not-loaded gate (NFR-SEC-01), end-to-end through the real boot + Store
#      path, before any listener binds, and no socket is bound on the refusal.
#   5. MANIFEST FLAG VALIDATION: each shipped deploy manifest's exact serving
#      argv (docker-compose, k8s, systemd) clears flag validation against the
#      real binary — it never exits on a missing/invalid REQUIRED flag. The
#      binary may still fail LATER (the signing-key path is absent in CI), which
#      is fine: this guards only that no manifest is one required flag short of
#      booting (the production blocker the readiness review found).
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
  -workload-profile trusted_operator
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
  -runtime-tier bogus -runtime-provider docker -workload-profile trusted_operator \
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
  -runtime-tier runc -runtime-provider podman -workload-profile trusted_operator \
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

# 3b. unknown workload profile — refused, never silently defaulted to a permissive
#     profile (a defaulted profile would silently widen the admission matrix).
code=0
out=$("$BIN" -operator-listen "$opsock" -gateway-listen "$gwsock" \
  -runtime-tier runc -runtime-provider docker -workload-profile wide-open \
  -jwt-signing-key "$tmp/jwt-signing.key" -audit-sink "$tmp/audit.ocsf.jsonl" 2>&1) || code=$?
echo "$out"
if [ "$code" -ne 1 ]; then
  echo "::error::expected exit 1 on unknown workload profile, got $code"
  fail=1
fi
echo "$out" | grep -q "unknown workload profile" || {
  echo "::error::unknown-workload-profile sentinel missing from output"
  fail=1
}

# 4. KILL-SWITCH-FIRST ORDERING — a create presented BEFORE the deny posture is
#    loaded is refused loudly by the transient not-loaded gate, naming NFR-SEC-01,
#    before any listener binds; and no socket exists.
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

# 4b. The kill-switch-first ordering refusal flows through the REAL boot + Store
#     path. An explicit empty -state-dsn (the in-memory minimal-shelf default)
#     must refuse the pre-load create identically, documenting the default and
#     confirming the create-on-start path exercises the live boot sequencer's
#     transient not-loaded gate, not a stub branch.
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

# 5. MANIFEST FLAG VALIDATION — each shipped manifest's exact serving argv clears
#    flag validation against the real binary. The argv mirrors the committed
#    manifest (deploy/docker-compose.yml command:, examples/k8s/control-deployment
#    .yaml args:, contrib/systemd/ocu-controld.service ExecStart=); the in-process
#    Go test (cmd/ocu-controld Test_Manifests_ClearFlagValidation_*) extracts the
#    SAME argv directly from those files, so a drift between this argv and a manifest
#    is caught there. Here we assert against the REAL binary: a valid argv must NOT
#    print a flag-validation sentinel. It is expected to fail LATER on the absent
#    signing key, so we assert on output content, never the exit code.
flag_sentinels='required flag missing or invalid|unknown runtime tier|unknown runtime provider|unknown workload profile|unknown jwt signing algorithm'

assert_clears_flags() {
  local label="$1"; shift
  local out
  out="$("$BIN" "$@" 2>&1)"
  if echo "$out" | grep -qE "$flag_sentinels"; then
    echo "::error::$label manifest argv tripped flag validation:"
    echo "$out"
    fail=1
  else
    echo "ok: $label manifest argv cleared flag validation (failed later on the absent key, as expected)"
  fi
}

# docker-compose command: (OCU_WORKLOAD_PROFILE default = untrusted, OCU_RUNTIME_TIER default = runc)
assert_clears_flags "docker-compose" \
  -operator-listen unix:///run/ocu-control/operator.sock \
  -gateway-listen 127.0.0.1:9466 \
  -runtime-tier runc -runtime-provider docker \
  -workload-profile untrusted \
  -jwt-signing-key /run/secrets/storage-jwt-signing.key \
  -audit-sink /var/log/ocu-control/audit.ocsf.jsonl

# k8s control-deployment.yaml args:
assert_clears_flags "k8s" \
  -operator-listen unix:///run/ocu-control/operator.sock \
  -gateway-listen 127.0.0.1:9466 \
  -runtime-tier runc -runtime-provider docker \
  -workload-profile untrusted \
  -jwt-signing-key /run/secrets/ocu-control/storage-jwt-signing.key \
  -audit-sink /var/log/ocu-control/audit.ocsf.jsonl

# systemd ocu-controld.service ExecStart=
assert_clears_flags "systemd" \
  -operator-listen unix:///run/ocu-control/operator.sock \
  -gateway-listen 127.0.0.1:9466 \
  -runtime-tier runc -runtime-provider docker \
  -workload-profile untrusted \
  -jwt-signing-key /etc/ocu-control/storage-jwt-signing.key \
  -audit-sink /var/log/ocu-control/audit.ocsf.jsonl

rm -rf "$tmp"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "real-binary smoke passed: four pre-bind refusals hold and all three manifest argvs clear flag validation"
