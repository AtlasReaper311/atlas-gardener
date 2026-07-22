#!/usr/bin/env python3
"""Collect and verify one completed Atlas Gardener autonomous canary."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

GATE_JOB = "gardener / Validate Gardener automatic merge"
BARRIER_JOB = "Gardener native auto-merge barrier"
GATE_REQUIRED_STEPS = {
    "Revalidate the automatic approval": "success",
    "Enable native squash auto-merge": "success",
    "Revoke workflow-owned auto-merge after refusal": "skipped",
}
BARRIER_REQUIRED_STEPS = {
    "Hold the native auto-merge barrier": "success",
}
EXPECTED_DISABLED_VARIABLES = {
    ("AtlasReaper311/atlas-dep-audit", "ATLAS_GARDENER_HANDOFF_ENABLED"): "false",
    ("AtlasReaper311/atlas-gardener", "ATLAS_GARDENER_MODE"): "disabled",
    ("AtlasReaper311/atlas-gardener", "ATLAS_GARDENER_WRITE_GATE"): "disabled",
    ("AtlasReaper311/atlas-gardener", "ATLAS_GARDENER_WRITE_TARGETS_JSON"): "[]",
}


class VerificationError(ValueError):
    """Raised when completed-canary evidence is incomplete or inconsistent."""


def canonical_app_login(value: str) -> str:
    """Normalise GitHub REST and GraphQL representations of one App actor."""
    result = value.removeprefix("app/")
    result = result.removesuffix("[bot]")
    return result


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return value


def _require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationError(f"{label} must be a JSON array")
    return value


def _job_by_name(jobs: list[Any], name: str) -> dict[str, Any]:
    matches = [item for item in jobs if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        raise VerificationError(f"expected exactly one workflow job named {name!r}")
    return matches[0]


def _validate_steps(job: dict[str, Any], expected: dict[str, str]) -> None:
    steps = _require_array(job.get("steps"), f"steps for {job.get('name', 'unknown job')}")
    states: dict[str, str] = {}
    for item in steps:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        conclusion = item.get("conclusion")
        if isinstance(name, str) and isinstance(conclusion, str):
            states[name] = conclusion.lower()
    for name, conclusion in expected.items():
        observed = states.get(name)
        if observed != conclusion:
            raise VerificationError(
                f"workflow step {name!r} expected {conclusion!r}, observed {observed!r}"
            )


def validate_canary(
    *,
    target_repository: str,
    pull_request_number: int,
    gate_run_id: int,
    expected_head_sha: str,
    expected_merge_sha: str,
    expected_app_login: str,
    expected_gardener_ref: str,
    expected_authority_ref: str,
    pr: dict[str, Any],
    run: dict[str, Any],
    jobs_document: dict[str, Any],
    repository: dict[str, Any],
    commit: dict[str, Any],
    variables: dict[str, str],
    gitignore: str,
    target_workflow: str,
) -> dict[str, Any]:
    """Validate structured GitHub evidence without relying on combined log text."""
    if pr.get("number") != pull_request_number:
        raise VerificationError("pull request number changed")
    if str(pr.get("state", "")).upper() != "MERGED" or not pr.get("mergedAt"):
        raise VerificationError("pull request is not recorded as merged")
    if pr.get("headRefOid") != expected_head_sha:
        raise VerificationError("pull request head SHA changed")
    if not str(pr.get("headRefName", "")).startswith("gardener/"):
        raise VerificationError("pull request head is outside the Gardener namespace")
    author = _require_object(pr.get("author"), "pull request author")
    author_login = str(author.get("login", ""))
    if canonical_app_login(author_login) != canonical_app_login(expected_app_login):
        raise VerificationError("pull request author is not the approved Gardener App")
    merge_commit = _require_object(pr.get("mergeCommit"), "pull request merge commit")
    if merge_commit.get("oid") != expected_merge_sha:
        raise VerificationError("pull request merge SHA changed")
    commits = _require_array(pr.get("commits"), "pull request commits")
    if len(commits) != 1:
        raise VerificationError("canary pull request must contain exactly one commit")
    files = _require_array(pr.get("files"), "pull request files")
    if len(files) != 1:
        raise VerificationError("canary pull request must change exactly one file")
    changed = _require_object(files[0], "pull request file")
    if changed.get("path") != ".gitignore":
        raise VerificationError("canary pull request changed a file other than .gitignore")
    if changed.get("additions") != 1 or changed.get("deletions") != 0:
        raise VerificationError("canary pull request is not the exact one-line addition")

    if run.get("id") != gate_run_id:
        raise VerificationError("gate run ID changed")
    if run.get("event") != "pull_request":
        raise VerificationError("gate run was not triggered by a pull request")
    if run.get("head_sha") != expected_head_sha:
        raise VerificationError("gate run head SHA changed")
    if str(run.get("status", "")).lower() != "completed":
        raise VerificationError("gate run did not complete")
    if str(run.get("conclusion", "")).lower() != "success":
        raise VerificationError("gate run did not succeed")

    jobs = _require_array(jobs_document.get("jobs"), "workflow jobs")
    gate_job = _job_by_name(jobs, GATE_JOB)
    barrier_job = _job_by_name(jobs, BARRIER_JOB)
    for job in (gate_job, barrier_job):
        if str(job.get("status", "")).lower() != "completed":
            raise VerificationError(f"workflow job {job.get('name')!r} did not complete")
        if str(job.get("conclusion", "")).lower() != "success":
            raise VerificationError(f"workflow job {job.get('name')!r} did not succeed")
    _validate_steps(gate_job, GATE_REQUIRED_STEPS)
    _validate_steps(barrier_job, BARRIER_REQUIRED_STEPS)

    if repository.get("full_name") not in {None, target_repository}:
        raise VerificationError("repository evidence targets the wrong repository")
    if repository.get("allow_auto_merge") is not False:
        raise VerificationError("repository native auto-merge was not returned to false")

    expected_variables = dict(EXPECTED_DISABLED_VARIABLES)
    expected_variables[(target_repository, "ATLAS_GARDENER_AUTOMERGE_ENABLED")] = "false"
    for key, expected in expected_variables.items():
        rendered_key = f"{key[0]}:{key[1]}"
        observed = variables.get(rendered_key)
        if observed != expected:
            raise VerificationError(
                f"repository variable {rendered_key} expected {expected!r}, observed {observed!r}"
            )

    if sum(line == ".DS_Store" for line in gitignore.splitlines()) != 1:
        raise VerificationError("target main must contain exactly one .DS_Store ignore rule")

    if f"gardener-automerge-gate.yml@{expected_gardener_ref}" not in target_workflow:
        raise VerificationError("target workflow is not pinned to the expected Gardener commit")
    if f"authority_ref: {expected_authority_ref}" not in target_workflow:
        raise VerificationError("target workflow is not pinned to the expected authority commit")

    if commit.get("sha") != expected_merge_sha:
        raise VerificationError("merge commit evidence targets the wrong SHA")
    commit_author = _require_object(commit.get("author"), "merge commit author")
    if canonical_app_login(str(commit_author.get("login", ""))) != canonical_app_login(
        expected_app_login
    ):
        raise VerificationError("merge commit author is not the approved Gardener App")
    commit_files = _require_array(commit.get("files"), "merge commit files")
    if len(commit_files) != 1:
        raise VerificationError("merge commit must change exactly one file")
    commit_file = _require_object(commit_files[0], "merge commit file")
    if commit_file.get("filename") != ".gitignore":
        raise VerificationError("merge commit changed a file other than .gitignore")
    if commit_file.get("additions") != 1 or commit_file.get("deletions") != 0:
        raise VerificationError("merge commit is not the exact one-line addition")

    return {
        "schema_version": "atlas-gardener/autonomous-canary-verification/v1",
        "status": "verified",
        "repository": target_repository,
        "pull_request": pull_request_number,
        "head_sha": expected_head_sha,
        "merge_sha": expected_merge_sha,
        "gate_run_id": gate_run_id,
        "app_actor": canonical_app_login(expected_app_login),
        "gate_job": GATE_JOB,
        "barrier_job": BARRIER_JOB,
        "native_auto_merge_step": "success",
        "refusal_cleanup_step": "skipped",
        "repository_auto_merge": False,
        "controls_disabled": True,
        "gitignore_ds_store_count": 1,
    }


def _run_gh(arguments: Sequence[str]) -> str:
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown gh failure"
        raise VerificationError(f"gh {' '.join(arguments[:3])} failed: {detail[:300]}")
    return completed.stdout


def _gh_json(
    arguments: Sequence[str],
    label: str,
    runner: Callable[[Sequence[str]], str],
) -> dict[str, Any]:
    try:
        value = json.loads(runner(arguments))
    except json.JSONDecodeError as error:
        raise VerificationError(f"{label} did not return valid JSON") from error
    return _require_object(value, label)


def collect_and_validate(
    *,
    target_repository: str,
    pull_request_number: int,
    gate_run_id: int,
    expected_head_sha: str,
    expected_merge_sha: str,
    expected_app_login: str,
    expected_gardener_ref: str,
    expected_authority_ref: str,
    runner: Callable[[Sequence[str]], str] = _run_gh,
) -> dict[str, Any]:
    pr = _gh_json(
        [
            "pr",
            "view",
            str(pull_request_number),
            "--repo",
            target_repository,
            "--json",
            "number,state,mergedAt,mergeCommit,author,headRefName,headRefOid,baseRefName,baseRefOid,commits,files",
        ],
        "pull request evidence",
        runner,
    )
    run = _gh_json(
        ["api", f"repos/{target_repository}/actions/runs/{gate_run_id}"],
        "gate run evidence",
        runner,
    )
    jobs = _gh_json(
        ["api", f"repos/{target_repository}/actions/runs/{gate_run_id}/jobs"],
        "gate job evidence",
        runner,
    )
    repository = _gh_json(
        ["api", f"repos/{target_repository}"],
        "repository evidence",
        runner,
    )
    commit = _gh_json(
        ["api", f"repos/{target_repository}/commits/{expected_merge_sha}"],
        "merge commit evidence",
        runner,
    )
    gitignore = runner(
        [
            "api",
            "-H",
            "Accept: application/vnd.github.raw+json",
            f"repos/{target_repository}/contents/.gitignore?ref=main",
        ]
    )
    target_workflow = runner(
        [
            "api",
            "-H",
            "Accept: application/vnd.github.raw+json",
            f"repos/{target_repository}/contents/.github/workflows/gardener-remediation-gate.yml?ref=main",
        ]
    )

    variables: dict[str, str] = {}
    variable_pairs = list(EXPECTED_DISABLED_VARIABLES)
    variable_pairs.append((target_repository, "ATLAS_GARDENER_AUTOMERGE_ENABLED"))
    for repository_name, variable_name in variable_pairs:
        value_document = _gh_json(
            [
                "variable",
                "get",
                variable_name,
                "--repo",
                repository_name,
                "--json",
                "value",
            ],
            f"variable {repository_name}:{variable_name}",
            runner,
        )
        variables[f"{repository_name}:{variable_name}"] = str(
            value_document.get("value", "")
        )

    return validate_canary(
        target_repository=target_repository,
        pull_request_number=pull_request_number,
        gate_run_id=gate_run_id,
        expected_head_sha=expected_head_sha,
        expected_merge_sha=expected_merge_sha,
        expected_app_login=expected_app_login,
        expected_gardener_ref=expected_gardener_ref,
        expected_authority_ref=expected_authority_ref,
        pr=pr,
        run=run,
        jobs_document=jobs,
        repository=repository,
        commit=commit,
        variables=variables,
        gitignore=gitignore,
        target_workflow=target_workflow,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--gate-run", required=True, type=int)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--app-login", required=True)
    parser.add_argument("--gardener-ref", required=True)
    parser.add_argument("--authority-ref", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = collect_and_validate(
            target_repository=args.repository,
            pull_request_number=args.pull_request,
            gate_run_id=args.gate_run,
            expected_head_sha=args.head_sha,
            expected_merge_sha=args.merge_sha,
            expected_app_login=args.app_login,
            expected_gardener_ref=args.gardener_ref,
            expected_authority_ref=args.authority_ref,
        )
    except VerificationError as error:
        print(f"Gardener canary verification failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
