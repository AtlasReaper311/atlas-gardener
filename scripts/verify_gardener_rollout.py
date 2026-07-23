#!/usr/bin/env python3
"""Collect and verify one completed Atlas Gardener low-risk rollout."""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

CANARY_PATH = Path(__file__).with_name("verify_gardener_canary.py")
SPEC = importlib.util.spec_from_file_location("verify_gardener_canary", CANARY_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {CANARY_PATH}")
CANARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CANARY)

ALLOWED_ADDED_LINES = ((".DS_Store",), ("", ".DS_Store"))


def _patch_lines(patch: str, prefix: str) -> list[str]:
    excluded = prefix * 3
    return [
        line[1:]
        for line in patch.splitlines()
        if line.startswith(prefix) and not line.startswith(excluded)
    ]


def validate_policy_patch(
    *,
    pr_files: list[Any],
    commit_files: list[Any],
) -> int:
    """Validate the exact policy-allowed macOS metadata ignore patch."""
    if len(pr_files) != 1 or not isinstance(pr_files[0], dict):
        raise CANARY.VerificationError("rollout pull request must change exactly one file")
    if len(commit_files) != 1 or not isinstance(commit_files[0], dict):
        raise CANARY.VerificationError("rollout merge commit must change exactly one file")

    pr_file = pr_files[0]
    commit_file = commit_files[0]
    for label, item, path_key in (
        ("pull request", pr_file, "filename"),
        ("merge commit", commit_file, "filename"),
    ):
        if item.get(path_key) != ".gitignore":
            raise CANARY.VerificationError(
                f"{label} changed a file other than .gitignore"
            )
        if item.get("deletions") != 0:
            raise CANARY.VerificationError(f"{label} contains a deletion")
        if item.get("additions") not in {1, 2}:
            raise CANARY.VerificationError(
                f"{label} exceeds the policy-allowed added-line boundary"
            )
        patch = item.get("patch")
        if not isinstance(patch, str):
            raise CANARY.VerificationError(f"{label} patch is unavailable")
        added = tuple(_patch_lines(patch, "+"))
        removed = _patch_lines(patch, "-")
        if added not in ALLOWED_ADDED_LINES or removed:
            raise CANARY.VerificationError(
                f"{label} is not the exact policy-allowed .DS_Store addition"
            )

    if pr_file.get("patch") != commit_file.get("patch"):
        raise CANARY.VerificationError(
            "pull request and merge commit patches are not identical"
        )
    return int(pr_file["additions"])


def collect_and_validate_rollout(
    *,
    target_repository: str,
    pull_request_number: int,
    gate_run_id: int,
    expected_head_sha: str,
    expected_merge_sha: str,
    expected_app_login: str,
    expected_gardener_ref: str,
    expected_authority_ref: str,
    runner: Callable[[Sequence[str]], str] = CANARY._run_gh,
) -> dict[str, Any]:
    """Collect rollout evidence and reuse the structured canary checks."""
    pr = CANARY._gh_json(
        [
            "pr",
            "view",
            str(pull_request_number),
            "--repo",
            target_repository,
            "--json",
            (
                "number,state,mergedAt,mergeCommit,author,headRefName,headRefOid,"
                "baseRefName,baseRefOid,commits,files"
            ),
        ],
        "pull request evidence",
        runner,
    )
    pr_files_document = json.loads(
        runner(
            [
                "api",
                f"repos/{target_repository}/pulls/{pull_request_number}/files?per_page=100",
            ]
        )
    )
    if not isinstance(pr_files_document, list):
        raise CANARY.VerificationError("pull request file evidence must be an array")
    run = CANARY._gh_json(
        ["api", f"repos/{target_repository}/actions/runs/{gate_run_id}"],
        "gate run evidence",
        runner,
    )
    jobs = CANARY._gh_json(
        ["api", f"repos/{target_repository}/actions/runs/{gate_run_id}/jobs"],
        "gate job evidence",
        runner,
    )
    repository = CANARY._gh_json(
        ["api", f"repos/{target_repository}"],
        "repository evidence",
        runner,
    )
    commit = CANARY._gh_json(
        ["api", f"repos/{target_repository}/commits/{expected_merge_sha}"],
        "merge commit evidence",
        runner,
    )
    commit_files = commit.get("files")
    if not isinstance(commit_files, list):
        raise CANARY.VerificationError("merge commit file evidence must be an array")
    actual_additions = validate_policy_patch(
        pr_files=pr_files_document,
        commit_files=commit_files,
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
            (
                f"repos/{target_repository}/contents/"
                ".github/workflows/gardener-remediation-gate.yml?ref=main"
            ),
        ]
    )

    variables: dict[str, str] = {}
    variable_pairs = list(CANARY.EXPECTED_DISABLED_VARIABLES)
    variable_pairs.append(
        (target_repository, "ATLAS_GARDENER_AUTOMERGE_ENABLED")
    )
    for repository_name, variable_name in variable_pairs:
        document = CANARY._gh_json(
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
            document.get("value", "")
        )

    # The canary validator intentionally encoded the original atlas-dora
    # one-line fixture. Patch exactness has already been verified above
    # against the authority's one-or-two-line policy, so normalise only
    # the summary counters before reusing every other structured check.
    normalised_pr = copy.deepcopy(pr)
    normalised_commit = copy.deepcopy(commit)
    normalised_pr["files"][0]["additions"] = 1
    normalised_commit["files"][0]["additions"] = 1

    report = CANARY.validate_canary(
        target_repository=target_repository,
        pull_request_number=pull_request_number,
        gate_run_id=gate_run_id,
        expected_head_sha=expected_head_sha,
        expected_merge_sha=expected_merge_sha,
        expected_app_login=expected_app_login,
        expected_gardener_ref=expected_gardener_ref,
        expected_authority_ref=expected_authority_ref,
        pr=normalised_pr,
        run=run,
        jobs_document=jobs,
        repository=repository,
        commit=normalised_commit,
        variables=variables,
        gitignore=gitignore,
        target_workflow=target_workflow,
    )
    report["schema_version"] = "atlas-gardener/autonomous-rollout-verification/v1"
    report["policy_patch_additions"] = actual_additions
    return report


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
        report = collect_and_validate_rollout(
            target_repository=args.repository,
            pull_request_number=args.pull_request,
            gate_run_id=args.gate_run,
            expected_head_sha=args.head_sha,
            expected_merge_sha=args.merge_sha,
            expected_app_login=args.app_login,
            expected_gardener_ref=args.gardener_ref,
            expected_authority_ref=args.authority_ref,
        )
    except (CANARY.VerificationError, json.JSONDecodeError) as error:
        print(f"Gardener rollout verification failed: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
