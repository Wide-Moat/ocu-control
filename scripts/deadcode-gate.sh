#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# GATE 1 (QUAL-01): the whole-program dead-code gate. It fails on ANY unreachable
# function across the module's build-plus-test graph, catching unreachable EXPORTS
# that the package-local unused check structurally cannot see.
#
# The gate runs `deadcode -test ./...` and fails on NON-EMPTY OUTPUT, never on the
# tool's exit status: deadcode exits 0 even when it reports findings, so keying the
# gate on $? would pass a tree full of dead code. The `-test` flag is load-bearing
# — it makes the deliberately-deferred operator handlers (the SOAR/deny/quota verbs
# kept tested-but-unmounted) and the firecracker NotImplemented stubs reachable
# from their unit tests, so they are correctly NOT flagged as dead without feeding
# the tool any exclusion list (it has none). The clean baseline is therefore
# literally empty, which is what makes "any output is a failure" a true rule.
set -euo pipefail

if ! command -v deadcode >/dev/null 2>&1; then
  echo "::error::deadcode not found on PATH"
  echo "  Install the pinned version:"
  echo "    go install golang.org/x/tools/cmd/deadcode@v0.38.0"
  echo "  and ensure \$(go env GOPATH)/bin is on PATH."
  exit 1
fi

out="$(deadcode -test ./...)"

if [ -n "$out" ]; then
  echo "::error::deadcode found unreachable functions (whole-program, incl. tests)"
  echo "$out"
  echo "  A reported function is dead and should be removed — UNLESS it is a"
  echo "  deliberately-deferred handler kept tested-but-unmounted. Those stay"
  echo "  reachable via their own unit tests under -test, so they never appear"
  echo "  here; see the deferredHandlers allow-list in internal/ingress/operator."
  echo "  If one does appear, its test fence has regressed — fix that, do not"
  echo "  suppress this gate."
  exit 1
fi

echo "deadcode: no unreachable functions"
