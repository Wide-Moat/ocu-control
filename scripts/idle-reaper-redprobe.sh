#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# RED-when-neutered proof for the idle-session reaper's two load-bearing steps in
# reapOne: the substrate FORCE-KILL and the concurrency-slot REFUND. A reaper that
# returns the slot without tearing down the container trades a slot leak for an
# orphan-container leak; a reaper that force-kills but never refunds the slot leaves
# the tier cap wedged. Each keystone must fail if the step it guards is removed, or
# the keystone guards nothing.
#
# This neuters each step in place (a text delete on the reapOne block in manager.go),
# asserts the matching keystone goes RED, restores the tree, and finally asserts the
# whole reaper keystone set is green on the clean code. Every neuter is reverted from
# git by the trap on every exit path, so a failed run never leaves the tree dirty.
set -euo pipefail

mgr="internal/lifecycle/manager.go"
pkg="./internal/lifecycle/"
teardown_keystone="TestReapIdle_AbandonedSessionReclaimed" # asserts liveCount()==0 AND slot==0

restore() { git checkout -- "$mgr" 2>/dev/null || true; }
trap restore EXIT

# The text the neuters delete. The force-kill guard line is unique to reapOne. The
# concurrency-refund CALL line (`m.ReleaseConcurrency(ctx, row.Owner)`) is NOT unique —
# the boot reconciler's reclaimOrphanRow returns a slot through the same call — so the
# neuter-2 guard keys on reapOne's UNIQUE error string ("release reaped concurrency"),
# not the shared call line, to detect whether reapOne's refund specifically is gone.
forcekill_line='if err := m.provider.Teardown().ForceKill(ctx, sandbox); err != nil {'
reap_refund_marker='release reaped concurrency'

for needle in "$forcekill_line" "$reap_refund_marker"; do
  if [ "$(grep -cF "$needle" "$mgr")" -lt 1 ]; then
    echo "::error::idle-reaper-redprobe is stale: expected '$needle' in $mgr"
    exit 1
  fi
done

# ---- Neuter 1: remove the FORCE-KILL. The abandoned container is never torn down,
#      so the keystone's liveCount()==0 assertion goes RED (orphan-container leak). We
#      replace the guarded force-kill with a no-op that keeps the block compiling but
#      never calls the provider teardown.
perl -0777 -i -pe 's/\Qif err := m.provider.Teardown().ForceKill(ctx, sandbox); err != nil {\E\n\t\tif !errors\.Is\(err, runtime\.ErrNoSuchContainer\) {\n\t\t\treturn fmt\.Errorf\("idle-reap force-kill: %w", err\)\n\t\t}\n\t}/_ = sandbox \/\/ NEUTERED: force-kill removed/' "$mgr"
if grep -qF "$forcekill_line" "$mgr"; then
  echo "::error::idle-reaper-redprobe failed to neuter the force-kill"
  exit 1
fi
if go test "$pkg" -run "$teardown_keystone" -count=1 >/dev/null 2>&1; then
  echo "::error::${teardown_keystone} PASSED with the reap force-kill removed — it does not guard the orphan-container leak"
  exit 1
fi
echo "ok: ${teardown_keystone} is RED with the reap force-kill neutered (orphan-container leak)"
restore

# ---- Neuter 2: remove the concurrency REFUND. The row is released but the tier-cap
#      slot is never returned, so the keystone's post-reap concurrency==0 assertion
#      goes RED (slot stuck). Replace the guarded refund with a no-op.
perl -0777 -i -pe 's/\Qif err := m.ReleaseConcurrency(ctx, row.Owner); err != nil {\E\n\t\treturn fmt\.Errorf\("release reaped concurrency: %w", err\)\n\t}/\/\/ NEUTERED: concurrency refund removed/' "$mgr"
# Key the guard on reapOne's UNIQUE error string, not the shared ReleaseConcurrency call
# line (which the boot reconciler also uses): the neuter is proven applied iff reapOne's
# "release reaped concurrency" text is gone.
if grep -qF "$reap_refund_marker" "$mgr"; then
  echo "::error::idle-reaper-redprobe failed to neuter the concurrency refund"
  exit 1
fi
if go test "$pkg" -run "$teardown_keystone" -count=1 >/dev/null 2>&1; then
  echo "::error::${teardown_keystone} PASSED with the reap concurrency refund removed — it does not guard the slot leak"
  exit 1
fi
echo "ok: ${teardown_keystone} is RED with the reap concurrency refund neutered (slot stuck)"
restore
trap - EXIT

# ---- Clean tree: the whole reaper keystone set must be green on the restored code.
if ! go test "$pkg" -run "TestReapIdle" -count=1 >/dev/null 2>&1; then
  echo "::error::the reaper keystones are RED on the clean tree (after restoring reapOne)"
  exit 1
fi
echo "ok: the reaper keystones are green on the restored code"

echo "idle-reaper-redprobe: the reap keystone fires RED when the force-kill OR the concurrency refund is removed, and green when both are restored"
