#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the cold-exec bounded-wait fix. A test that stays
# green when the fix it guards is reverted proves nothing (the warm-guest false-
# green that masked this race in the first place). This script neuters the fix in
# place — swaps the bounded re-dial poll back for the plain single dial the driver
# had before — asserts the cold-exec keystone goes RED, restores the tree, and
# asserts the keystone goes green again on the clean fix.
#
# The neutering is a text swap on internal/guestexec/driver.go, reverted from git
# on every exit path by the trap, so a failed run never leaves the tree dirty.
set -euo pipefail

driver="internal/guestexec/driver.go"
keystone="TestDriverExecWaitsForColdSocket"
pkg="./internal/guestexec/"

# The exact call the fix introduced, and the plain single dial it replaced. The
# neuter reverts the former to the latter — the pre-fix behaviour that returns the
# cold ENOENT verbatim instead of waiting for the socket to come up.
fixed_call='ch, err := dialWithColdWait(ctx, filepath.Join(sockDir, execSockName), minter)'
prefix_call='ch, err := dial.DialUDS(ctx, filepath.Join(sockDir, execSockName), minter)'

restore() { git checkout -- "$driver" 2>/dev/null || true; }
trap restore EXIT

# Guard: the fixed call must be present exactly once, or the probe is stale.
if [ "$(grep -cF "$fixed_call" "$driver")" != "1" ]; then
  echo "::error::coldexec-redprobe is stale: expected exactly one '$fixed_call' in $driver"
  exit 1
fi

# (1) Neuter the fix: revert the bounded-wait dial to the plain single dial.
#     Use a perl in-place edit on the fixed-string so no regex metachars bite.
perl -i -pe "s/\Q${fixed_call}\E/${prefix_call}/" "$driver"
if ! grep -qF "$prefix_call" "$driver"; then
  echo "::error::coldexec-redprobe failed to neuter the fix"
  exit 1
fi

# (2) With the fix neutered, the cold-exec keystone MUST go RED. Capture the status
#     rather than letting set -e abort on the expected failure.
if go test "$pkg" -run "$keystone" -count=1 >/dev/null 2>&1; then
  echo "::error::${keystone} PASSED with the cold-exec fix neutered — the test guards nothing (warm-false-green)"
  exit 1
fi
echo "ok: ${keystone} is RED with the bounded-wait fix reverted to a plain single dial"

# (3) Restore the fix and confirm the keystone goes green again on the clean tree.
restore
trap - EXIT
if ! go test "$pkg" -run "$keystone" -count=1 >/dev/null 2>&1; then
  echo "::error::${keystone} is RED on the clean tree (after restoring the fix)"
  exit 1
fi
echo "ok: ${keystone} is green on the restored fix"

echo "coldexec-redprobe: keystone fires RED when the bounded-wait fix is neutered and green when restored"
