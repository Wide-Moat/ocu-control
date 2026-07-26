<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Recovery: what the deployed `ocu-control:fleet` binary contains that git does not

Written 2026-07-26 from firsthand inspection of the running stand. Every statement
below names the command that produced it. Nothing here is from memory.

## The trigger

The running control container is started with `-storage-ttl 2h`. Go's `flag`
package terminates the process on an undefined flag, and the container has been
healthy for days, so the binary defines that flag. No ref in this repo does.

## What the binary is

```
$ limactl shell ocu-linux -- docker inspect ocu-donegate-control-1 \
    --format '{{.Image}} {{.Config.Image}}'
sha256:772bd717ba12ade072c3ea4c48572e6c7ed6e0a281b33b77b6c6caa58028b109 ocu-control:fleet
created=2026-07-19T05:53:56+03:00
```

Note the tag is ambiguous across daemons: the host's Docker Desktop holds a
DIFFERENT image also tagged `ocu-control:fleet` (`8bb63489c83a`, 2026-07-04). Only
the one inside the Lima VM is the deployed artifact.

## Flag-surface diff, measured not recalled

The binary's defined flag names were probed by extracting it and testing membership
of each candidate name against its string table:

```
$ limactl shell ocu-linux -- bash -c \
    'cid=$(docker create ocu-control:fleet); \
     docker cp $cid:/usr/local/bin/ocu-controld /tmp/ocuc-fleet; docker rm $cid'
$ limactl shell ocu-linux -- strings -n 6 /tmp/ocuc-fleet > /tmp/ocuc-strings.txt
```

| surface | flags |
|---|---|
| `main` | 29 |
| stage tree `~/donegate-stage/ocu-control` (not a git repo) | 33 |
| branch `donegate/control-tree` | 34 |
| deployed binary | 35 (all 35 candidates present) |

Deployed minus `main` is six flags:

| flag | where it exists in git |
|---|---|
| `-storage-ttl` | **nowhere. Absent from all 75 refs and from the whole stage tree.** |
| `-operator-socket-gid` | `feat/operator-socket-gid`, `donegate/control-tree` |
| `-log-level` | `fast-follow/structured-logging`, `donegate/control-tree`, 2 more |
| `-log-format` | same |
| `-derive-chat-scope` | `fix/146-plural-mount-intents`, `donegate/control-tree`, 2 more |
| `-storage-scope-base` | same |

Deployed minus `donegate/control-tree` is exactly one flag: `-storage-ttl`.
`donegate/control-tree` is 11 commits ahead of `main` and 0 behind.

So the deployed binary corresponds to `donegate/control-tree` plus one change that
was never committed anywhere. The build is not reproducible, but the gap is one
flag, not a lost tree.

## Why provenance cannot be read off the artifact

```
$ go version -m ocuc-fleet
    mod  github.com/Wide-Moat/ocu-control  (devel)
    dep  github.com/Wide-Moat/ocu-sandbox/host/exec  v0.1.0
    =>   ./third_party/sandbox-host-exec  (devel)
    build  -trimpath=true
    build  CGO_ENABLED=0
    build  GOARCH=arm64
```

There is **no `vcs.revision`, `vcs.time`, or `vcs.modified` build setting**. Go
stamps those only when building from a git worktree; their absence means the build
ran against a copied tree. That is consistent with the stage-tree layout and it is
the mechanical reason the artifact cannot name its own source.

The `=> ./third_party/sandbox-host-exec` replace corroborates the branch
identification: that vendor directory arrives in `donegate/control-tree`'s head
commit, `5595613 STAGE-ONLY: vendor ocu-sandbox host/exec for the DONE-gate boot`.

## The stage tree is not the source

`~/donegate-stage/ocu-control` has no `.git`, its newest file predates 2026-07-18,
and it does not contain `-storage-ttl`:

```
$ find ~/donegate-stage/ocu-control -newermt "2026-07-18" -type f | wc -l
0
$ grep -rl "storage-ttl" ~/donegate-stage
(no output)
```

It is an older copy (33 flags), not the tree the 2026-07-19 image was built from.

## What this commit restores

`-storage-ttl` is reconstructed from observed behaviour only: the name and the fact
that it takes a duration, both established from the running container's arguments.
Two things about the deployed flag are NOT observable and are therefore decisions
recorded here rather than recoveries:

- **Its default.** The deployed stand passes `2h` explicitly, so the binary's own
  default was never exercised and cannot be read back. This restores it with the
  15-minute default `main` already uses for the constant, so a deployment that
  omits the flag gets today's behaviour.
- **Whether it has a ceiling.** The deployed binary accepts `2h`, so it has no
  ceiling at or below that. Adding one now would refuse the running stand's own
  arguments on the next rebuild, so this restores it uncapped and rejects only a
  non-positive value. Whether a ceiling belongs is a ruling to make deliberately,
  not a detail to smuggle in under a recovery.

## Session lifetime, restated across both artifacts

The `#192` memo describes a 15-minute window. That is correct for a build from
`main` and wrong for what is running:

- deployed binary: `-storage-ttl 2h`
- built from `main`: 15 minutes, the constant

Neither has a refresh channel, so the chosen fix (a pre-`exp` re-mint and
re-provisioning push) is the right answer for both. The window width only changes
how soon the defect is reached.
