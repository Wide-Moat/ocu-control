#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the release-path structural gate.
#
# check-signing-precedes-publish.py is the one part of the signed-artifact gate that
# CAN be required on a pull request, because it reads workflow files rather than
# artifacts. That makes its own vacuity the risk: a checker whose publish-detection
# stops matching (an action renamed, a different spelling of the same push) passes
# everything and reports success, and a green required check over a blind checker is
# exactly the shape the gate exists to prevent.
#
# So this plants the regression the checker exists to catch -- a consumable tag
# attached ahead of the signature -- in BOTH spellings, and requires the checker to
# reject each. The planting happens in a COPY of the workflow directory, so the probe
# never mutates the tree it is proving.
#
# Two spellings, because a checker that catches one and misses the other reports a
# clean release path while an unsigned tag ships: a false PASS, the worse direction.
# The second spelling is the one a checker reading only `with.tags` and `with.push`
# misses -- the tag hides inside the `outputs` string and neither key is present.
# This repository's own checker had that exact gap until it was measured.
set -euo pipefail

checker="scripts/check-signing-precedes-publish.py"
[ -f "$checker" ] || { echo "::error::${checker} not found"; exit 1; }

# (1) The real tree must PASS. If it does not, the gate is red for a real reason and
# the probe below would be meaningless.
if ! python3 "$checker" >/dev/null; then
  echo "::error::the release path already fails the signing-precedes-publish check; fix that before trusting this proof"
  exit 1
fi
echo "ok: the real release path passes"

# run_spelling replaces the digest-only push line with one planted publishing form and
# asserts the checker rejects the result. The digest-only marker is asserted present
# first, so a release path that stopped pushing by digest fails loudly here instead of
# silently planting nothing and "passing".
run_spelling() {
  local label="$1" replacement="$2" work target
  work="$(mktemp -d)"
  mkdir -p "$work/.github/workflows"
  cp .github/workflows/*.yml "$work/.github/workflows/"
  cp "$checker" "$work/checker.py"
  target="$work/.github/workflows/release.yml"

  if ! grep -q "push-by-digest=true" "$target"; then
    rm -rf "$work"
    echo "::error::the digest-only push shape is gone from release.yml; the probe cannot plant its defect"
    exit 1
  fi

  PROBE_TARGET="$target" PROBE_REPLACEMENT="$replacement" python3 -c '
import os, re
path = os.environ["PROBE_TARGET"]
repl = os.environ["PROBE_REPLACEMENT"]
text = open(path).read()
text = re.sub(
    r"^(\s*)outputs: type=image.*push-by-digest=true.*$",
    lambda m: "\n".join(m.group(1) + line for line in repl.split("\n")),
    text,
    count=1,
    flags=re.M,
)
open(path, "w").write(text)
'

  if (cd "$work" && python3 checker.py >/dev/null 2>&1); then
    rm -rf "$work"
    echo "::error::the checker ACCEPTED a workflow publishing a consumable tag ahead of the signature (spelling: ${label}). Its publish-detection does not match this spelling, so it would report a clean release path while an unsigned tag ships."
    exit 1
  fi
  rm -rf "$work"
  echo "ok: checker is RED on the planted regression (spelling: ${label})"
}

# Spelling 1: the conventional keys, the shape that existed before the promote split.
run_spelling "tags+push keys" 'push: true
tags: ghcr.io/planted/probe:v0.0.0'

# Spelling 2: the tag hidden inside the outputs string, with no tags: and no push: key.
run_spelling "tag inside outputs" 'outputs: type=image,name=ghcr.io/planted/probe:v0.0.0,push=true'

echo "signing-precedes-publish-redprobe: the checker rejects the regression it exists to catch, in both spellings"
