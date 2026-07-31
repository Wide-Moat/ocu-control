#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the release-path structural gate.
#
# check-signing-precedes-publish.py is the one part of the signed-artifact gate that
# CAN be required on a pull request, because it reads workflow files rather than
# artifacts. That makes its own vacuity the risk: a checker whose publish-detection
# stops matching (an action renamed, a new publishing verb) passes everything and
# reports success, and a green required check over a blind checker is exactly the
# shape the gate exists to prevent.
#
# So this plants the regression the checker exists to catch -- a tag attached by the
# publishing job, ahead of the signature -- and requires the checker to REJECT it. The
# planting happens in a COPY of the workflow directory, so the probe never mutates the
# tree it is proving.
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

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

mkdir -p "$work/.github/workflows"
cp .github/workflows/*.yml "$work/.github/workflows/"
cp "$checker" "$work/checker.py"

# Plant the defect: give the digest-only push a consumable tag, which is precisely the
# shape that existed before the promote split.
python3 - "$work/.github/workflows/release.yml" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
needle = "push-by-digest=true"
if needle not in text:
    print("::error::the digest-only push shape is gone from release.yml; the probe cannot plant its defect")
    raise SystemExit(1)
text = re.sub(
    r"^(\s*)outputs: type=image.*push-by-digest=true.*$",
    r"\1push: true\n\1tags: ghcr.io/planted/probe:v0.0.0",
    text,
    count=1,
    flags=re.M,
)
open(path, "w").write(text)
PY

if (cd "$work" && python3 checker.py >/dev/null 2>&1); then
  echo "::error::the checker ACCEPTED a workflow that attaches a consumable tag ahead of the signature. Its publish-detection no longer matches how this repo publishes, so it guards nothing."
  exit 1
fi
echo "ok: checker is RED on a planted publish-before-sign regression"

echo "signing-precedes-publish-redprobe: the checker rejects the regression it exists to catch"
