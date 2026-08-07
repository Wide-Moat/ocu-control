#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Red-probe the RPC-surface breaking-change gate: prove rpc-version-check.sh
# reddens on a planted breaking change, and passes on the tree as committed.
#
# This gate spent its whole life reporting a confident green while skipping. It
# probed `buf.yaml` at the repo root and `contracts/operator/openapi.yaml`; the
# contracts landed at `contracts/proto/buf.yaml` and `contracts/openapi/*.yaml`,
# so the detection never fired and the notice said "no wire surface present yet"
# with three diffable surfaces sitting in the tree. A gate that cannot tell
# "nothing to check" from "not looking" is the failure this probe exists to
# catch, so the probe asserts the gate ENFORCES, never merely that it exits 0.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

readonly GATE="scripts/rpc-version-check.sh"
if [ ! -f "$GATE" ]; then
  echo "::error::$GATE not found; the probe cannot measure the gate (fail-closed)"
  exit 1
fi

# The surfaces the gate must be watching. Derived from the tree rather than
# restated: a probe with its own hardcoded list would keep passing after a
# contract moved, which is the exact drift that produced the bug.
mapfile -t SURFACES < <(git ls-files 'contracts/openapi/*.yaml' | grep -v redocly || true)
if [ "${#SURFACES[@]}" -eq 0 ]; then
  echo "::error::no contracts/openapi/*.yaml tracked; either the surfaces moved again or"
  echo "::error::this probe is measuring a tree that has none (fail-closed)"
  exit 1
fi
echo "probe derives ${#SURFACES[@]} OpenAPI surface(s) from the tree: ${SURFACES[*]}"

if ! command -v oasdiff >/dev/null 2>&1; then
  echo "::error::oasdiff is not installed; the probe cannot prove the gate enforces"
  exit 1
fi

# The COMMIT, not the branch name: CI checks out a detached HEAD, where
# rev-parse --abbrev-ref HEAD answers the literal string "HEAD" and restoring
# it is a no-op, so a planted commit would survive cleanup and the clean arm
# would then fail against the probe's own plant.
start_ref="$(git rev-parse HEAD)"
readonly start_ref
start_branch="$(git symbolic-ref -q --short HEAD 2>/dev/null || true)"
readonly start_branch

cleanup() {
  git rev-parse --verify -q rpcprobe-scratch >/dev/null 2>&1 || return 0
  # --force, because the probe's own plant leaves the tree dirty relative to the
  # ref being restored. Without it the checkout refuses, the scratch branch
  # cannot be deleted while it is checked out, and the caller is stranded on it
  # with a planted breaking change in the tree — running this locally would then
  # cost manual repair, which is the failure a cleanup exists to prevent.
  git checkout -q --force --detach "$start_ref" 2>/dev/null || true
  git branch -q -D rpcprobe-scratch 2>/dev/null || true
  if [ -n "$start_branch" ]; then
    git checkout -q --force "$start_branch" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Refuse to run against uncommitted work. --force above discards whatever is in
# the tree, so a probe started on a dirty checkout would destroy the caller's
# edits to make its own cleanup safe. CI checks out clean, so this only ever
# fires on a workstation.
if ! git diff --quiet HEAD 2>/dev/null; then
  echo "::error::the working tree has uncommitted changes; this probe plants a commit"
  echo "::error::and force-restores afterwards, which would discard them. Commit or stash first."
  exit 1
fi

# (1) CLEAN: the tree as committed must pass against its own parent.
if ! bash "$GATE" HEAD^ >/dev/null 2>&1; then
  echo "::error::the gate reds on the tree as committed; a real breaking change is present,"
  echo "::error::or the gate is broken. Run: bash $GATE HEAD^"
  exit 1
fi
echo "ok: gate is green on the tree as committed"

# (2) PLANTED: removing a required response from an operation is breaking by
# oasdiff's own rules. The plant is committed to a scratch branch because the
# gate diffs git refs, which is the path a real change takes.
target="${SURFACES[0]}"
# -B, not -b: a run killed before its trap fires leaves the scratch branch
# behind, and -b would abort on it.
git checkout -q -B rpcprobe-scratch

python3 - "$target" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
# Delete the first documented 2xx response block. Removing a success response an
# existing client depends on is breaking by oasdiff's own rules.
#
# The key quoting is matched loosely ('200', "200" and bare 200 are all legal
# YAML) so the probe does not silently stop planting when a contract is
# reformatted -- a probe that cannot plant reports the same green as a gate that
# cannot detect.
m = re.search(r'\n(\s+)[\'"]?2\d\d[\'"]?:\n(?:\1\s+.*\n|[ \t]*\n)+', s)
if not m:
    sys.exit("probe could not find a 2xx response to remove in " + p)
open(p, "w").write(s[:m.start()] + "\n" + s[m.end():])
PY

git add "$target"
git -c user.email=rpcprobe@localhost -c user.name=rpcprobe \
  commit -q -m "probe: removed a required response (scratch branch, never pushed)"

# The gate must REDDEN. Its exit status is captured rather than left to set -e,
# because a non-zero exit is the expected outcome here.
if bash "$GATE" "$start_ref" >/dev/null 2>&1; then
  echo "::error::the gate reported NO breaking change after a required 200 response was"
  echo "::error::removed from $target. Either the gate is not detecting this surface (check"
  echo "::error::the detection paths in $GATE against where the contracts actually live), or"
  echo "::error::oasdiff is not being run. A gate that finds a planted break nowhere finds a"
  echo "::error::real one nowhere."
  exit 1
fi
echo "ok: gate is RED on a planted breaking change ($target)"

cleanup
trap - EXIT
echo "rpc-version-redprobe: the gate enforces on a real surface and is green on a clean tree"
