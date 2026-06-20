# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert every in-scope source file carries the SPDX FSL-1.1-Apache-2.0 header
# within its first three lines.
#
# Scope is the set of git-tracked files (so untracked/ignored build trees are
# never scanned). The scope is an EXPLICIT allowlist of path globs, declared in
# IN_SCOPE below, so it can never silently drift as the tree grows.
#
# IN SCOPE (shipped source that must carry the SPDX header):
#   *.go                       — daemon source
#   *.sh                       — shell tooling
#   .github/workflows/*.yml    — CI workflow definitions
#   Dockerfile                 — the shipped build recipe
#   contrib/systemd/*.service  — the shipped systemd unit
#   contracts/openapi/*.yaml   — the OpenAPI 3.1 wire surfaces this repo defines,
#                                plus their redocly lint config; YAML comment SPDX.
#   contracts/proto/**/*.proto — the gRPC wire surfaces this repo defines; // SPDX.
#   contracts/proto/buf.yaml   — the proto module/lint config; YAML comment SPDX.
#
# DELIBERATELY OUT OF SCOPE (documented so the omission is a decision, not a
# gap):
#   *.md                 — docs/prose; license is covered by the repo LICENSE.
#   examples/k8s/*.yaml  — Kubernetes manifests; YAML/k8s convention is no
#                          per-file SPDX, and the LICENSE governs them.
#   contracts/*.json     — JSON carries its own $comment SPDX and is checked by
#                          the contract-identity script, not here.
#   LICENSE*, NOTICE     — license texts themselves.
#
# The SPDX token is matched as a fixed string; comment lines are never
# bare-counted.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly TOKEN='SPDX-License-Identifier: FSL-1.1-Apache-2.0'

# Explicit in-scope path globs (see the header for the rationale and the
# documented out-of-scope set). Edit this list to change scope — there is no
# implicit catch-all.
readonly -a IN_SCOPE=(
  '*.go'
  '*.sh'
  '.github/workflows/*.yml'
  'Dockerfile'
  'contrib/systemd/*.service'
  'contracts/openapi/*.yaml'
  'contracts/proto/*.yaml'
  'contracts/proto/**/*.proto'
)

misses=()

while IFS= read -r file; do
  if ! head -n 3 "$file" | grep -qF -- "$TOKEN"; then
    misses+=("$file")
  fi
done < <(git ls-files "${IN_SCOPE[@]}")

if [ "${#misses[@]}" -gt 0 ]; then
  # One annotation per miss: printf reuses its format across every remaining
  # argument, so a single format with two placeholders fed the whole array
  # would pair the token with the wrong file from the second miss on. Loop
  # instead so each file is named correctly in its own ::error:: line.
  for f in "${misses[@]}"; do
    printf '::error::missing SPDX header (%s): %s\n' "$TOKEN" "$f"
  done
  echo "Add the SPDX FSL-1.1-Apache-2.0 header to the files above (see CLAUDE.md)." >&2
  exit 1
fi

echo "SPDX header present on all in-scope source files"
