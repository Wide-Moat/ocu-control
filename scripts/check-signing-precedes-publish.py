#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
"""Assert no workflow job publishes a consumable image reference before signing.

WHY THIS IS A FILE CHECK AND NOT AN ARTIFACT CHECK. The signed-SBOM/provenance gate
lives on the release path, which runs on a tag; branch protection evaluates pull
requests, so that gate can never be a required PR check. Worse, GitHub counts a
SKIPPED required check as passed, so moving it to a PR job behind a condition would
produce a permanently green check that blocks nothing. What CAN be required on a PR
is a check that reads the workflow files themselves -- it needs no artifact, so it
runs anywhere, and it fails the PR that would have introduced the regression.

WHAT IT ENFORCES. cosign signs by digest, so the push necessarily happens before the
signature exists; "sign before push" is not an achievable invariant. The achievable
one is: no reference a consumer would pull may exist before the signature. A digest
nobody has been told is not such a reference. A release tag is. So a job that
attaches a TAG to a registry reference must depend, directly or transitively, on the
job that signs.

It is deliberately conservative about what counts as publishing: pushing by digest
alone is not flagged, because that is the only way to have something to sign.
"""

from __future__ import annotations

import pathlib
import sys

import yaml

WORKFLOW_DIR = pathlib.Path(".github/workflows")

# Substrings that mark a step as ATTACHING A TAG (a consumable reference), as opposed
# to pushing content by digest.
TAG_PUBLISH_MARKERS = ("imagetools create", "docker push", "docker tag")

# Substrings that mark a step as producing a signature or attestation.
SIGNING_MARKERS = ("cosign sign", "attest-build-provenance", "cosign attest")


def step_text(step: dict) -> str:
    """Flatten the parts of a step that can carry a command or an action ref."""
    parts = [str(step.get("run", "")), str(step.get("uses", ""))]
    with_block = step.get("with") or {}
    if isinstance(with_block, dict):
        parts.extend(f"{k}={v}" for k, v in with_block.items())
    return "\n".join(parts)


def job_publishes_a_tag(job: dict) -> bool:
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        text = step_text(step)
        if any(marker in text for marker in TAG_PUBLISH_MARKERS):
            return True
        # build-push-action publishes a consumable reference when it pushes AND is
        # given tags. Pushing with `push-by-digest=true` and no tags does not.
        uses = str(step.get("uses", ""))
        with_block = step.get("with") or {}
        if "docker/build-push-action" in uses and isinstance(with_block, dict):
            tags = str(with_block.get("tags", "")).strip()
            outputs = str(with_block.get("outputs", ""))
            pushes = (
                str(with_block.get("push", "")).strip().lower() == "true"
                or "push=true" in outputs
            )
            if not pushes:
                continue
            if tags:
                return True
            # The tag can also hide INSIDE the outputs string, as
            # `type=image,name=ghcr.io/org/repo:v1.2.3,push=true`, with no `tags:`
            # key and no `push:` key at all. Reading only `with.tags`/`with.push`
            # misses it, and the miss is a FALSE PASS -- the worse direction, since
            # it reports a clean release path that is publishing a consumable tag.
            if outputs_name_carries_tag(outputs):
                return True
    return False


def outputs_name_carries_tag(outputs: str) -> bool:
    """True if a build-push-action `outputs` string names a TAGGED image reference.

    `push-by-digest=true` is the digest-only form and is never a consumable tag, so it
    short-circuits regardless of what `name=` holds.
    """
    if "push-by-digest=true" in outputs:
        return False
    for field in outputs.split(","):
        field = field.strip()
        if not field.startswith("name="):
            continue
        ref = field[len("name="):].strip().strip('"')
        # A tag is a colon in the LAST path segment; a colon earlier is a registry
        # port (localhost:5000/img), which is not a tag.
        last = ref.rsplit("/", 1)[-1]
        if ":" in last:
            return True
    return False


def job_signs(job: dict) -> bool:
    for step in job.get("steps") or []:
        if isinstance(step, dict) and any(m in step_text(step) for m in SIGNING_MARKERS):
            return True
    return False


def needs_of(job: dict) -> list[str]:
    needs = job.get("needs")
    if needs is None:
        return []
    return [needs] if isinstance(needs, str) else list(needs)


def reaches(start: str, target: str, jobs: dict, seen: set[str] | None = None) -> bool:
    """True if start transitively depends on target."""
    seen = seen or set()
    for dep in needs_of(jobs.get(start) or {}):
        if dep in seen:
            continue
        seen.add(dep)
        if dep == target or reaches(dep, target, jobs, seen):
            return True
    return False


def check_workflow(path: pathlib.Path) -> list[str]:
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        return [f"{path}: could not parse: {exc}"]
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return []

    signing_jobs = [name for name, job in jobs.items() if isinstance(job, dict) and job_signs(job)]
    if not signing_jobs:
        # No signing in this workflow: nothing to order against. A workflow that
        # publishes and never signs at all is a different (louder) problem, and is
        # not this check's claim to make.
        return []

    failures = []
    for name, job in jobs.items():
        if not isinstance(job, dict) or not job_publishes_a_tag(job):
            continue
        if name in signing_jobs:
            continue
        if not any(reaches(name, signer, jobs) for signer in signing_jobs):
            failures.append(
                f"{path.name}: job `{name}` attaches a consumable tag without depending on "
                f"the signing job(s) {signing_jobs}. A pullable reference would exist before "
                f"the signature. Push by digest here and attach tags in a job that "
                f"`needs:` the signer."
            )
    return failures


def main() -> int:
    if not WORKFLOW_DIR.is_dir():
        print(f"::error::{WORKFLOW_DIR} not found; run from the repository root")
        return 1
    failures = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml")):
        failures.extend(check_workflow(path))
    if failures:
        for f in failures:
            print(f"::error::{f}")
        return 1
    print("signing-precedes-publish: no job attaches a consumable tag ahead of the signature")
    return 0


if __name__ == "__main__":
    sys.exit(main())
