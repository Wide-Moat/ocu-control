#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the secrets gate. A secrets scanner given a config
# with an allowlist but no rules and no [extend] scans with ZERO detection rules,
# so every committed secret passes — a vacuous gate that guards nothing. This script
# proves .gitleaks.toml actually detects secrets: it plants a real (non-example)
# credential, runs gitleaks with the repo config exactly as CI does, and asserts the
# scan goes RED (a leak is reported). Then it removes the secret and asserts the scan
# is clean. A trap removes the probe on every exit path so a failed run never leaves
# the tree dirty.
#
# If this script passes while [extend]/useDefault is removed from .gitleaks.toml, the
# gate is vacuous — that is exactly the regression this probe exists to catch.
set -euo pipefail

# gitleaks is required: a missing scanner must FAIL the probe (fail-closed), never
# skip it green — a silent skip is itself a vacuous gate.
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "::error::gitleaks not found on PATH; the secrets red-probe cannot run (fail-closed)"
  exit 1
fi

probe_file="zz_gitleaks_redprobe_secret.txt"

cleanup() { rm -f "$probe_file"; }
trap cleanup EXIT

# A real, non-example GitLab PAT shape the gitleaks default ruleset detects. It is a
# structurally valid but entirely fake token (never a live credential); the point is
# only that the default detectors match its shape. AWS "EXAMPLE" keys are deliberately
# avoided — the default ruleset allowlists them as documentation placeholders.
#
# The planted value is assembled at runtime from parts so this literal does NOT appear
# verbatim in the script source — otherwise the tree-scan would flag the script itself
# and need an allowlist entry, and that entry (matching the value) would also suppress
# the planted temp-file match, defeating the probe. Assembling it here keeps the
# detectable literal out of any committed file, so no allowlist can hide it.
planted="glpat-$(printf 'PROBE')onlyFAKE0987654321"
printf 'gitlab_pat = "%s"\n' "$planted" >"$probe_file"

# (1) With the planted secret, the scan MUST report a leak (non-zero exit). Capture
# the status rather than letting `set -e` abort on the expected failure. --no-git
# scans the working tree so the probe need not be committed. The config is
# auto-discovered from .gitleaks.toml in the repo root, exactly as the CI step runs it.
if gitleaks detect --source=. --config=.gitleaks.toml --no-git --redact --no-banner >/dev/null 2>&1; then
  echo "::error::gitleaks reported NO leak on a planted GitLab PAT — the secrets gate is scanning with no rules (a config without [extend]/useDefault replaces the default ruleset). Restore '[extend]\n  useDefault = true' in .gitleaks.toml."
  exit 1
fi
echo "ok: gate is RED on a planted secret (gitleaks detected the GitLab PAT)"

# (2) Remove the probe and confirm the scan is clean on the tree.
cleanup
trap - EXIT
if ! gitleaks detect --source=. --config=.gitleaks.toml --no-git --redact --no-banner >/dev/null 2>&1; then
  echo "::error::gitleaks reported a leak on the clean tree (after removing the probe) — a real secret may be committed, or the probe file was not removed"
  exit 1
fi
echo "ok: gate is clean on the tree (no committed secrets)"

echo "gitleaks-redprobe: gate fires RED on a planted secret and clean when the tree has none"
