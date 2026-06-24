#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for GATE 1 — the first of the two default-wrong skeptics.
# A gate that never fires guards nothing, so this script proves scripts/deadcode-
# gate.sh actually catches dead code: it plants an exported, never-called function
# in a real internal package, asserts the gate goes RED, removes it, and asserts the
# gate goes green on the clean tree. A trap removes the probe on every exit path so a
# failed run never leaves the tree dirty.
set -euo pipefail

# Plant the probe in a real internal package, reading its package name from the tree
# so a rename never silently breaks the probe.
probe_dir="internal/admission"
probe_file="${probe_dir}/zz_deadprobe.go"
probe_pkg="$(go list -f '{{.Name}}' "./${probe_dir}")"

cleanup() { rm -f "$probe_file"; }
trap cleanup EXIT

cat >"$probe_file" <<EOF
// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ${probe_pkg}

// DeadProbe is a deliberately unreachable exported function planted by
// scripts/deadcode-redprobe.sh to prove the dead-code gate fires. The trap in that
// script removes this file; it must never be committed.
func DeadProbe() {}
EOF

# (1) With the planted dead export, the gate MUST go RED. Capture the exit status
# rather than letting `set -e` abort on the expected failure.
if bash scripts/deadcode-gate.sh >/dev/null 2>&1; then
  echo "::error::deadcode gate did NOT fire on a planted dead export — the gate guards nothing"
  exit 1
fi
echo "ok: gate is RED on a planted dead export (admission.DeadProbe)"

# (2) Remove the probe and confirm the gate goes green on the clean tree.
cleanup
trap - EXIT
if ! bash scripts/deadcode-gate.sh >/dev/null 2>&1; then
  echo "::error::deadcode gate is RED on the clean tree (after removing the probe)"
  exit 1
fi
echo "ok: gate is green on the clean tree"

echo "deadcode-redprobe: gate fires RED on a planted dead export and green when clean"
