#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert the embedded Docker-provider seccomp profile is byte-identical to its
# pinned upstream revision. The profile is adopted third-party content (the moby
# default deny-default profile) embedded with //go:embed and applied verbatim as
# the seccomp= SecurityOpt on every container the provider materializes. Drifting
# its bytes silently would change the enforced syscall posture, so the sha256 is
# pinned in the provenance README and re-checked here: any edit to default.json
# that is not a deliberate re-pin (README + this script updated together) fails
# the gate.
set -euo pipefail

dir="internal/runtime/docker/seccomp"
profile="$dir/default.json"
readme="$dir/README.md"

# The pinned digest. Keep in sync with the sha256: line in the provenance README
# when (and only when) deliberately adopting a newer upstream profile.
pinned="536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74"

if [ ! -f "$profile" ]; then
  echo "::error::seccomp profile missing at $profile"
  exit 1
fi

actual="$(shasum -a 256 "$profile" | awk '{print $1}')"

if [ "$actual" != "$pinned" ]; then
  echo "::error::seccomp profile $profile sha256 $actual != pinned $pinned"
  echo "  If this is a deliberate upstream re-pin, update the sha256: line in"
  echo "  $readme AND the pinned digest in this script in the same commit, and"
  echo "  re-run the real-Docker integration leg to prove a container still starts."
  exit 1
fi

# The README must carry the same digest, so the provenance record and the gate
# never drift apart.
if ! grep -q "$pinned" "$readme"; then
  echo "::error::pinned sha256 $pinned is not recorded in $readme"
  exit 1
fi

echo "seccomp profile matches its pinned digest ($pinned)"
