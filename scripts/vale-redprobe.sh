#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for GATE 2 — the default-wrong skeptic. A prose gate
# that never fires guards nothing, so this script proves scripts/vale-gate.sh
# actually catches banned vocabulary: it appends a planted banned line to a real
# canon-critical doc, asserts the gate goes RED, restores the doc, and asserts the
# gate goes green again. A trap restores the file on every exit path so a failed
# run never leaves the tree dirty.
#
# The probe word ("comprehensive") is drawn from the vendored banned-vocab token
# list, and the line is plain prose (not inside a code fence or front-matter), so
# it exercises the live banlist through the same TokenIgnores/BlockIgnores the
# gate uses — a probe inside a fence would prove nothing because the gate
# correctly ignores fenced content.
set -euo pipefail

# Probe a real canon-critical (blocking-tier) doc so the RED path is the blocking
# path, not the non-blocking warning tier.
probe_file="CONTRIBUTING.md"
backup="$(mktemp)"

cleanup() {
  if [ -f "$backup" ]; then
    cp "$backup" "$probe_file"
    rm -f "$backup"
  fi
}
trap cleanup EXIT

cp "$probe_file" "$backup"

# Append a banned-vocabulary line as plain prose (outside any code fence). The
# trailing blank keeps the file well-formed; the banlist match is on the word.
printf '\nThis is a comprehensive and robust planted probe line; vale must flag it.\n' >>"$probe_file"

# (1) With the planted banned vocabulary, the gate MUST go RED. Capture the exit
# status rather than letting `set -e` abort on the expected failure.
if bash scripts/vale-gate.sh >/dev/null 2>&1; then
  echo "::error::vale gate did NOT fire on planted banned vocabulary in ${probe_file} — the gate guards nothing"
  exit 1
fi
echo "ok: gate is RED on planted banned vocabulary (${probe_file})"

# (2) Restore the doc and confirm the gate goes green on the clean tree.
cleanup
trap - EXIT
if ! bash scripts/vale-gate.sh >/dev/null 2>&1; then
  echo "::error::vale gate is RED on the clean tree (after restoring ${probe_file})"
  exit 1
fi
echo "ok: gate is green on the clean tree"

echo "vale-redprobe: gate fires RED on planted banned vocabulary and green when clean"
