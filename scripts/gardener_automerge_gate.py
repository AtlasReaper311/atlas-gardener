#!/usr/bin/env python3
"""Validate one target repository Gardener PR before native auto-merge is enabled."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from atlas_gardener.automation import (
    object_digest,
    parse_approval_marker,
    read_object,
    validate_policy,
)
from atlas_gardener.errors import GardenerError, SafetyRefusal

SUCCESS_STATES = {"SUCCESS", "NEUTRAL"}
PENDING_STATES = {"EXPECTED", "PENDING", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED"}
FAILURE_STATES = {
    "ACTION_REQUIRED",
    "CANCELLED",
    "ERROR",
    "FAILURE",
    "SKIPPED",
    "STALE",
    "TIMED_OUT",
}


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SafetyRefusal(f"cannot read valid {label}: {error}") from error


def _check_names(pr: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in pr.get("statusCheckRollup") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("context")
        state = item.get("conclusion") or item.get("state") or item.get("status")
        if isinstance(name, str) and isinstance(state, str):
            result[name] = state.upper()
    return result


def _patch_added_lines(files: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    added: list[str] = []
    removed: list[str] = []
    for item in files:
        patch = item.get("patch")
        if not isinstance(patch, str):
            raise SafetyRefusal("pull request patch is missing or unbounded")
        for line in patch.splitlines():
            if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
                continue
            if line.startswith("+"):
                added.append(line[1:])
            elif line.startswith("-"):
                removed.append(line[1:])
    return added, removed


def validate_gate(
    *,
    pr: dict[str, Any],
    files: list[dict[str, Any]],
    policy: dict[str, Any],
    coverage: dict[str, Any],
    expected_app_login: str,
    required_checks: list[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    validate_policy(policy, coverage)
    repository = os.environ.get("GITHUB_REPOSITORY") or pr.get("repository")
    if not isinstance(repository, str) or not repository.startswith("AtlasReaper311/"):
        raise SafetyRefusal("target repository identity is unavailable")
    author = pr.get("author") or {}
    if author.get("login") != expected_app_login:
        raise SafetyRefusal("pull request author is not the approved Gardener App bot")
    if pr.get("state") != "OPEN" or pr.get("isDraft") is not False:
        raise SafetyRefusal("automatic merge requires an open ready pull request")
    head_branch = pr.get("headRefName")
    if not isinstance(head_branch, str) or not head_branch.startswith("gardener/"):
        raise SafetyRefusal("pull request head is outside the Gardener branch namespace")
    approval = parse_approval_marker(str(pr.get("body") or ""))
    if approval.get("repository") != repository:
        raise SafetyRefusal("approval repository identity mismatch")
    if approval.get("mode") != "automerge-low-risk" or approval.get("risk_class") != "low":
        raise SafetyRefusal("approval is not an automatic low-risk approval")
    if approval.get("expected_head_sha") != pr.get("headRefOid"):
        raise SafetyRefusal("pull request head changed after approval")
    if approval.get("base_branch") != pr.get("baseRefName"):
        raise SafetyRefusal("pull request base branch changed after approval")
    if approval.get("base_sha") != pr.get("baseRefOid"):
        raise SafetyRefusal("pull request base commit changed after approval")
    if approval.get("policy_digest") != object_digest(policy):
        raise SafetyRefusal("committed automation policy changed after approval")
    if approval.get("coverage_digest") != object_digest(coverage):
        raise SafetyRefusal("public coverage policy changed after approval")
    current = now or datetime.now(timezone.utc)
    try:
        expires = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
    except ValueError as error:
        raise SafetyRefusal("approval expiry is invalid") from error
    if expires.tzinfo is None or current > expires:
        raise SafetyRefusal("automatic approval expired")
    fixer_id = approval.get("fixer", {}).get("id")
    fixer_policy = policy["fixers"].get(fixer_id)
    if not isinstance(fixer_policy, dict) or fixer_policy.get("automatic_merge") is not True:
        raise SafetyRefusal("fixer is review-only under current policy")
    commits = pr.get("commits") or []
    if len(commits) != 1:
        raise SafetyRefusal("automatic merge requires exactly one Gardener commit")
    commit_oid = commits[0].get("oid") if isinstance(commits[0], dict) else None
    if commit_oid != approval["expected_head_sha"]:
        raise SafetyRefusal("pull request contains an unexpected commit")
    if len(files) != 1:
        raise SafetyRefusal("automatic merge requires exactly one changed file")
    item = files[0]
    if item.get("filename") != ".gitignore" or item.get("status") not in {"added", "modified"}:
        raise SafetyRefusal("automatic merge is restricted to .gitignore additions")
    if int(item.get("deletions", 0)) != 0:
        raise SafetyRefusal("automatic merge cannot delete lines")
    if int(item.get("additions", 0)) > policy["automatic_merge_limits"]["maximum_changed_lines"]:
        raise SafetyRefusal("automatic merge line bound exceeded")
    added, removed = _patch_added_lines(files)
    if removed:
        raise SafetyRefusal("automatic merge patch is not additions-only")
    allowed_lines = set(fixer_policy["automatic_merge_added_lines"])
    if not added or any(line not in allowed_lines for line in added):
        raise SafetyRefusal("automatic merge patch contains an unexpected line")
    approval_files = approval.get("files")
    if not isinstance(approval_files, list) or len(approval_files) != 1:
        raise SafetyRefusal("approval file list is invalid")
    if approval_files[0].get("path") != ".gitignore" or approval_files[0].get("mode") != "100644":
        raise SafetyRefusal("approval file or mode boundary changed")
    if not required_checks:
        raise SafetyRefusal("missing required-check configuration cannot be treated as success")
    states = _check_names(pr)
    missing = sorted(set(required_checks) - set(states))
    if missing:
        raise SafetyRefusal("required checks are missing: " + ", ".join(missing))
    failed = sorted(name for name in required_checks if states[name] in FAILURE_STATES)
    pending = sorted(name for name in required_checks if states[name] in PENDING_STATES)
    unknown = sorted(
        name
        for name in required_checks
        if states[name] not in SUCCESS_STATES | PENDING_STATES | FAILURE_STATES
    )
    if failed:
        raise SafetyRefusal("required checks failed: " + ", ".join(failed))
    if pending:
        raise SafetyRefusal("required checks are still pending: " + ", ".join(pending))
    if unknown:
        raise SafetyRefusal("required checks returned unknown states: " + ", ".join(unknown))
    return {
        "schema_version": "atlas-gardener/automerge-gate-result/v1",
        "eligible": True,
        "repository": repository,
        "pull_request": pr.get("number"),
        "head_sha": pr.get("headRefOid"),
        "approval_id": approval["approval_id"],
        "remediation_key": approval["remediation_key"],
        "required_checks": sorted(required_checks),
        "merge_method": "squash",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pr", required=True, type=Path)
    parser.add_argument("--files", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--coverage", required=True, type=Path)
    parser.add_argument("--expected-app-login", required=True)
    parser.add_argument("--required-checks", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        required_checks = json.loads(args.required_checks)
        if not isinstance(required_checks, list) or any(not isinstance(value, str) or not value for value in required_checks):
            raise SafetyRefusal("required checks must be a JSON array of non-empty names")
        result = validate_gate(
            pr=load_json(args.pr, "pull request JSON"),
            files=load_json(args.files, "pull request files JSON"),
            policy=read_object(args.policy, label="automation policy"),
            coverage=read_object(args.coverage, label="coverage policy"),
            expected_app_login=args.expected_app_login,
            required_checks=required_checks,
        )
    except (GardenerError, OSError, ValueError) as error:
        print(f"Gardener auto-merge gate refused: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write("eligible=true\n")
            handle.write(f"approval_id={result['approval_id']}\n")
            handle.write(f"remediation_key={result['remediation_key']}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
