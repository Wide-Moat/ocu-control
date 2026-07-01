# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Flag the stale maintainer identity in tracked files. The canonical contact
# address is developer@widemoat.ai; the retired one must not survive in
# committed docs, code, comments, or commit-referenced text. This is a doc
# quality gate (run everywhere), not a leak guard.
#
# Scope: tracked files only. Pass paths as arguments to limit the scan;
# with no arguments, scan the whole tracked tree. This script holds the
# stale literal as a plain string and excludes its own path from the scan
# with a git-grep pathspec, so the literal here never reports as a hit.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly STALE='i@yambr.com'
readonly CANON='developer@widemoat.ai'

# Exclude this script's own path: it carries the stale literal by design as
# the pattern to search for, and must not flag itself. The pathspec is
# relative to the repo root (we cd'd there above).
readonly SELF_EXCLUDE=':!scripts/check-doc-identity.sh'

# Limit to provided paths, else the whole tracked tree. -F fixed string;
# --no-color so the grep output is clean for CI logs.
if [ "$#" -gt 0 ]; then
  hits=$(git grep -n --no-color -F -e "$STALE" -- "$@" "$SELF_EXCLUDE" || true)
else
  hits=$(git grep -n --no-color -F -e "$STALE" -- "$SELF_EXCLUDE" || true)
fi

if [ -n "$hits" ]; then
  echo "::error::stale maintainer identity '$STALE' found in tracked files"
  echo "Rewrite it to the canonical address: $CANON" >&2
  echo "$hits" | sed 's/^/  /' >&2
  exit 1
fi

echo "no stale maintainer identity in tracked files"
