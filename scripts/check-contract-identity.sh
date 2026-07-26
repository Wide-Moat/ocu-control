# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Assert every vendored contract copy has not drifted from the canonical
# architecture-repo source. The canonical contracts live in the
# Wide-Moat/open-computer-use repository under contracts/; this repo vendors
# byte-identical copies so any Go parity test (and any future embed) always
# builds against the pinned wire surface.
#
# Pinned canon revision (next/v1): 099d3d7 — next/v1 after PR #318,
# "feat(contracts): freeze the mcp-key-set artifact and operator mcp-key verbs
# (ADR-0027)". All five declared contracts are byte-identical to canon at this
# rev (verified by cmp): mcp/mcp-key-set.schema.json enters at this pin (git
# blob 25329b0f…); control-rpc, exec-channel, mount-config, and audit-fanin are
# unchanged since the prior pin 5100e14 (PR #303 exec-uplift: snake_case rename
# + the TraceEvent 5-field $defs + zstd RFC 8878 window ≤2^17 pins; exec-channel
# sha256 ea1e94ef…52aaf, control-rpc bd0bde46…). Keep this pin in sync with the
# canon checkout `ref:` in go.yml's checks job. Bump it deliberately when
# re-vendoring and verify byte-identity (cmp) before bumping.
#
# The canon is a SEPARATE repository, so this check runs wherever a checkout
# is reachable (set OCU_CANON_DIR, default ../open-computer-use) and skips
# with a notice where it is not (CI without the sibling checkout). The
# in-repo gate that always runs is the schema-compile check; this script is
# the sync alarm for the vendored copies themselves.
#
# The canon side is read from the PINNED REVISION with `git show`, never from the
# checkout's working tree. Reading the working tree made the gate's verdict depend
# on which branch the developer happened to have checked out next door: a canon
# checkout parked on an unrelated branch reported phantom drift (or a missing
# contract) for files that are byte-identical to canon at the pin, and an
# uncommitted edit in that checkout could just as easily have made a drifted
# vendored copy pass. Neither outcome is a property of this repo, which is what the
# gate is supposed to be measuring. CI already checks the canon out AT the pinned
# SHA, so this makes a local run mean the same thing a CI run means.
#
# OCU_CANON_REV overrides the pin (a deliberate re-vendoring against a canon branch
# needs it). The literal value `worktree` restores the old working-tree read and
# says so loudly: it is for authoring a re-vendor, not for gating.
set -euo pipefail

cd "$(dirname "$0")/.."

readonly CANON_DIR="${OCU_CANON_DIR:-../open-computer-use}"
# Pinned canon revision; keep in sync with the header above and with go.yml's
# canon checkout `ref:`.
readonly CANON_REV="${OCU_CANON_REV:-099d3d76d6d8a8e5bec6f46b989c6b9a9246c375}"

# The declared set of vendored contracts, by path under contracts/ on both
# sides. Add a path here when a contract is vendored; the loop below fails
# loud if a declared path is missing from EITHER the canon or this repo, so
# the set cannot silently fall out of sync with what is actually vendored.
readonly -a CONTRACTS=(
  'control/control-rpc.schema.json'
  'exec/exec-channel.schema.json'
  'storage/mount-config.schema.json'
  'audit/audit-fanin.asyncapi.yaml'
  'mcp/mcp-key-set.schema.json'
)

# Resolve the canon side once: probe the first declared contract to decide
# whether a canon checkout is present at all.
readonly CANON_PROBE="$CANON_DIR/contracts/${CONTRACTS[0]}"
if [ ! -f "$CANON_PROBE" ]; then
  # An explicitly named canon dir that lacks the schema is an error (CI
  # checks the canon out and must never skip-pass); only the implicit
  # local-default path may be absent (developer machine without the
  # sibling checkout).
  if [ -n "${OCU_CANON_DIR:-}" ]; then
    echo "::error::OCU_CANON_DIR is set but $CANON_PROBE is missing"
    exit 1
  fi
  echo "::notice::canon checkout not present ($CANON_PROBE); skipping identity check"
  exit 0
fi

# Resolve the canon revision unless the worktree escape hatch is requested. A
# checkout that is not a git repo, or one that does not contain the pinned commit
# (a shallow or stale clone), is a HARD failure: the alternative is falling back to
# the working tree, which is exactly the unsound read this gate no longer does.
if [ "$CANON_REV" != "worktree" ]; then
  if ! git -C "$CANON_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    echo "::error::canon checkout $CANON_DIR is not a git repository, so the pinned revision cannot be read"
    exit 1
  fi
  if ! git -C "$CANON_DIR" cat-file -e "$CANON_REV^{commit}" 2>/dev/null; then
    echo "::error::canon checkout $CANON_DIR does not contain pinned revision $CANON_REV"
    echo "Fetch it: git -C $CANON_DIR fetch origin $CANON_REV" >&2
    exit 1
  fi
else
  echo "::warning::OCU_CANON_REV=worktree — comparing against the canon WORKING TREE, whose contents depend on the checked-out branch. Advisory only; not a gate."
fi

# canonBytes writes the canon side of one contract to stdout, from the pinned
# revision (or the working tree under the escape hatch). A missing path exits
# non-zero and prints nothing, which the caller reports as a missing contract.
canonBytes() {
  local rel="$1"
  if [ "$CANON_REV" = "worktree" ]; then
    cat -- "$CANON_DIR/contracts/$rel"
  else
    git -C "$CANON_DIR" show "$CANON_REV:contracts/$rel"
  fi
}

drift=0
for rel in "${CONTRACTS[@]}"; do
  vendored="contracts/$rel"
  canon_desc="$CANON_DIR@${CANON_REV:0:12}:contracts/$rel"
  if [ ! -f "$vendored" ]; then
    echo "::error::declared contract '$rel' is not vendored in this repo ($vendored)"
    drift=1
    continue
  fi
  # Materialise the canon side to a temp file so cmp reports a real path and a
  # retrieval failure is distinguishable from a byte difference.
  tmp="$(mktemp)"
  if ! canonBytes "$rel" >"$tmp" 2>/dev/null; then
    echo "::error::declared contract '$rel' is missing from the canon ($canon_desc)"
    rm -f -- "$tmp"
    drift=1
    continue
  fi
  if ! cmp -- "$tmp" "$vendored"; then
    echo "::error::vendored contract drifted: $vendored != $canon_desc"
    drift=1
  fi
  rm -f -- "$tmp"
done

if [ "$drift" -ne 0 ]; then
  echo "Re-vendor the canonical schema; the contract changes in the architecture repo first." >&2
  exit 1
fi

echo "all vendored contracts are byte-identical to the canon"
