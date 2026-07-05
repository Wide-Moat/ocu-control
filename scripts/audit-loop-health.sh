#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# audit-loop-health.sh — self-healing preflight for the self-audit /loop.
#
# Run at the top of every loop tick BEFORE advancing the finder queue. It
# diagnoses the recoverable failure modes of a long-running background audit and
# repairs the mechanical ones in place; anything it cannot safely repair it
# reports with an ESCALATE line so the tick surfaces it to the architect instead
# of silently stalling.
#
# It is READ-MOSTLY: the only writes are worktree teardown and a tree restore to
# a clean checkout of the tracked HEAD — both are recovery from an interrupted
# worktree-per-probe, never a mutation of shipped state. It never pushes, never
# commits, never touches a branch other than the current checkout.
#
# Exit status: 0 = healthy or fully repaired; 1 = an ESCALATE condition remains.
# Every finding is printed as one of: OK / FIXED / ESCALATE.

set -u
REPO="${OCU_CONTROL_REPO:-/Users/nick/ocu-control}"
cd "$REPO" || { echo "ESCALATE repo-missing: $REPO not a directory"; exit 1; }

rc=0
say()  { printf '%s\n' "$*"; }
fail() { rc=1; say "$@"; }

# 1) On the main checkout and no detached/stray branch left by an aborted probe.
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
if [ "$branch" = "main" ]; then
  say "OK branch: on main"
else
  fail "ESCALATE branch: expected main, on '$branch' (an audit-fix branch may be mid-flight — do NOT auto-switch; confirm the PR state first)"
fi

# 2) Tracked tree clean. A *tracked* modification after a probe means an
#    interrupted worktree-per-probe left a mutation in a shipped path — restore
#    only that. Untracked files are NOT probe debris (they are new scaffolding
#    like this script), so they are reported, never stashed away.
if [ -z "$(git status --porcelain --untracked-files=no)" ]; then
  say "OK tree: no tracked modifications"
  untracked="$(git ls-files --others --exclude-standard)"
  [ -n "$untracked" ] && say "OK tree: untracked files present (left as-is): $(echo "$untracked" | tr '\n' ' ')"
else
  say "FIXED tree: tracked modification detected — restoring shipped paths to clean HEAD (interrupted probe recovery)"
  git stash push --quiet --message "audit-loop-health autostash $(git rev-parse --short HEAD)" 2>/dev/null || true
  # Leave the stash in place as a safety net; report it so it is not lost.
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    fail "ESCALATE tree: still has tracked changes after autostash — manual inspection required (git status)"
  else
    say "FIXED tree: shipped paths clean after autostash (recover with 'git stash list' if the mutation was real work)"
  fi
fi

# 3) No orphaned worktrees. The known hazard: a TaskStop'd go-mutesting leaves a
#    worktree with mutated source; a later 'git checkout' in it produces false
#    600s go-test timeouts. Any worktree other than the main checkout is stale.
mapfile -t wt < <(git worktree list --porcelain | awk '/^worktree /{print $2}')
stale=0
for w in "${wt[@]}"; do
  if [ "$w" != "$REPO" ]; then
    stale=1
    say "FIXED worktree: removing orphan $w"
    git -C "$REPO" worktree remove --force "$w" 2>/dev/null \
      || fail "ESCALATE worktree: could not remove $w (remove by hand: git -C $REPO worktree remove --force $w)"
  fi
done
git -C "$REPO" worktree prune 2>/dev/null || true
[ "$stale" -eq 0 ] && say "OK worktree: no orphans"

# 4) No orphaned CPU-burn / go-mutesting processes from a killed probe (the
#    orphan hazard). Report loudly; killing another session's job would be
#    hostile, so this only reports — the tick decides.
burns="$(pgrep -f 'go-mutesting|cpu-burn|go test .*-run' 2>/dev/null | wc -l | tr -d ' ')"
if [ "${burns:-0}" -gt 0 ]; then
  say "ESCALATE procs: $burns possible orphaned go-mutesting/go-test/cpu-burn processes (pgrep -af 'go-mutesting|cpu-burn'); confirm none is a live probe before killing"
  # not a hard failure by itself unless it blocks a probe; leave rc as set
else
  say "OK procs: no orphaned mutation/test processes"
fi

exit $rc
