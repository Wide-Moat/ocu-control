# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RPC-surface versioning gate (NFR-IC-04). The control-plane RPC surface is
# versioned: a breaking change to the operator/gateway wire surface requires a
# MAJOR version bump plus a deprecation header, and this check enforces it in CI
# by diffing the current surface against the merge base.
#
# The operator-REST / proto WIRE schemas are a deferred follow-up (#205): the v1
# control-plane ships its wire surface as the FROZEN JSON-Schema contracts under
# contracts/ (control-rpc, exec-channel, mount-config) and the audit-fanin
# AsyncAPI, none of which is a proto/OpenAPI surface buf/oasdiff can breaking-diff.
# Until the operator proto/OpenAPI schemas land, this gate is a CLEARLY-SCOPED
# NO-OP: it detects the absence of a diffable surface and SKIPS with a notice
# (exit 0) so the workflow is wired and green from commit 1, then begins enforcing
# the moment the schemas are committed. It does NOT fabricate a schema to gate.
#
# Usage:  bash scripts/rpc-version-check.sh [BASE_REF]
#   BASE_REF defaults to origin/main; in CI the workflow passes the PR base.
#
# Detection (any one present switches the gate from skip to enforce):
#   - a buf module:           buf.yaml | buf.gen.yaml  (proto surface → buf breaking)
#   - an OpenAPI surface:     contracts/operator/openapi.yaml (→ oasdiff breaking)
#
# When a surface IS present the gate runs the matching breaking-change tool against
# BASE_REF and FAILS on a breaking delta that is not accompanied by a MAJOR bump.
set -uo pipefail

BASE_REF="${1:-origin/main}"

note() { echo "::notice::rpc-version-check: $*"; }
err() { echo "::error::rpc-version-check: $*"; }

# Resolve the repo root so the check is independent of the caller's cwd.
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || { err "cannot cd to repo root"; exit 2; }

BUF_MODULE=""
for f in buf.yaml buf.gen.yaml; do
  if [ -f "$f" ]; then BUF_MODULE="$f"; break; fi
done

OPENAPI_SURFACE=""
if [ -f "contracts/operator/openapi.yaml" ]; then
  OPENAPI_SURFACE="contracts/operator/openapi.yaml"
fi

if [ -z "$BUF_MODULE" ] && [ -z "$OPENAPI_SURFACE" ]; then
  note "no operator proto/OpenAPI wire surface present yet (deferred follow-up #205)."
  note "the v1 wire surface is the frozen JSON-Schema contracts under contracts/; there is"
  note "nothing for buf/oasdiff to breaking-diff. SKIPPING (no-op-until-schemas), exit 0."
  note "this gate begins enforcing automatically when buf.yaml or contracts/operator/openapi.yaml lands."
  exit 0
fi

rc=0

if [ -n "$BUF_MODULE" ]; then
  if ! command -v buf >/dev/null 2>&1; then
    err "buf module $BUF_MODULE present but the buf CLI is not installed in CI."
    exit 2
  fi
  note "buf module detected ($BUF_MODULE); running buf breaking against $BASE_REF."
  if ! buf breaking --against ".git#ref=$BASE_REF"; then
    err "buf detected a BREAKING change to the proto RPC surface against $BASE_REF."
    err "a breaking change requires a MAJOR version bump + a deprecation header (NFR-IC-04)."
    rc=1
  fi
fi

if [ -n "$OPENAPI_SURFACE" ]; then
  if ! command -v oasdiff >/dev/null 2>&1; then
    err "OpenAPI surface $OPENAPI_SURFACE present but the oasdiff CLI is not installed in CI."
    exit 2
  fi
  note "OpenAPI surface detected ($OPENAPI_SURFACE); running oasdiff breaking against $BASE_REF."
  BASE_TMP="$(mktemp)"
  if git show "$BASE_REF:$OPENAPI_SURFACE" >"$BASE_TMP" 2>/dev/null; then
    if ! oasdiff breaking "$BASE_TMP" "$OPENAPI_SURFACE" --fail-on ERR; then
      err "oasdiff detected a BREAKING change to the OpenAPI RPC surface against $BASE_REF."
      err "a breaking change requires a MAJOR version bump + a deprecation header (NFR-IC-04)."
      rc=1
    fi
  else
    note "$OPENAPI_SURFACE is new at this ref (no base to diff); first introduction is not a breaking change."
  fi
  rm -f "$BASE_TMP"
fi

if [ "$rc" -eq 0 ]; then
  note "RPC surface is compatible with $BASE_REF (no unversioned breaking change)."
fi
exit "$rc"
