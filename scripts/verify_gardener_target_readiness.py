#!/usr/bin/env python3
"""Read-only verification of Gardener target repository readiness."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


class ReadinessError(ValueError):
    """Raised when a target is not ready for bounded automatic remediation."""


def _run_gh(arguments: Sequence[str]) -> str:
    completed = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown gh failure"
        raise ReadinessError(f"gh {' '.join(arguments[:3])} failed: {detail[:300]}")
    return completed.stdout


def _json_object(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ReadinessError(f"{label} did not return valid JSON") from error
    if not isinstance(value, dict):
        raise ReadinessError(f"{label} must be a JSON object")
    return value


def required_check_contexts(protection: dict[str, Any]) -> set[str]:
    contexts = {
        value
        for value in protection.get("contexts", [])
        if isinstance(value, str) and value
    }
    for item in protection.get("checks", []):
        if isinstance(item, dict) and isinstance(item.get("context"), str):
            contexts.add(item["context"])
    return contexts


def validate_target(
    *,
    policy: dict[str, Any],
    target: dict[str, Any],
    repository: dict[str, Any],
    variable_value: str,
    workflow: str,
    protection: dict[str, Any],
    expected_gardener_ref: str,
    expected_authority_ref: str,
) -> dict[str, Any]:
    repository_name = target["repository"]
    if repository.get("full_name") not in {None, repository_name}:
        raise ReadinessError(f"repository evidence mismatch for {repository_name}")
    settings = policy["required_repository_settings"]
    if repository.get("allow_squash_merge") is not settings["allow_squash_merge"]:
        raise ReadinessError(f"{repository_name} does not allow squash merge")
    if repository.get("allow_auto_merge") is not settings["allow_auto_merge_at_rest"]:
        raise ReadinessError(f"{repository_name} native auto-merge is not disabled at rest")
    if variable_value != policy["disabled_value"]:
        raise ReadinessError(f"{repository_name} target variable is not disabled at rest")

    required_fragments = [
        f"gardener-automerge-gate.yml@{expected_gardener_ref}",
        f"authority_ref: {expected_authority_ref}",
        f"expected_app_login: {policy['expected_app_login']}",
    ]
    for fragment in required_fragments:
        if fragment not in workflow:
            raise ReadinessError(f"{repository_name} target caller is missing {fragment}")
    branch_scope = (
        "vars.ATLAS_GARDENER_AUTOMERGE_ENABLED == 'true' && "
        "startsWith(github.event.pull_request.head.ref, 'gardener/')"
    )
    if workflow.count(branch_scope) != 2:
        raise ReadinessError(f"{repository_name} caller does not scope both jobs to Gardener branches")

    required = set(target["required_checks"])
    required.add(policy["barrier_check"])
    observed = required_check_contexts(protection)
    missing = sorted(required - observed)
    if missing:
        raise ReadinessError(
            f"{repository_name} branch protection is missing required checks: {', '.join(missing)}"
        )
    return {
        "repository": repository_name,
        "status": "ready",
        "required_checks": sorted(required),
        "repository_auto_merge": False,
        "target_variable": policy["disabled_value"],
    }


def collect_and_validate(
    *,
    policy_path: Path,
    expected_gardener_ref: str,
    expected_authority_ref: str,
    selected_repositories: set[str] | None = None,
    runner: Callable[[Sequence[str]], str] = _run_gh,
) -> dict[str, Any]:
    policy = _json_object(policy_path.read_text(encoding="utf-8"), "readiness policy")
    targets = policy.get("targets")
    if not isinstance(targets, list):
        raise ReadinessError("readiness policy targets must be an array")

    reports = []
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("repository"), str):
            raise ReadinessError("readiness target is malformed")
        repository_name = target["repository"]
        if selected_repositories and repository_name not in selected_repositories:
            continue
        repository = _json_object(
            runner(["api", f"repos/{repository_name}"]),
            f"repository {repository_name}",
        )
        variable = _json_object(
            runner(
                [
                    "variable",
                    "get",
                    policy["target_variable"],
                    "--repo",
                    repository_name,
                    "--json",
                    "value",
                ]
            ),
            f"variable {repository_name}",
        )
        workflow = runner(
            [
                "api",
                "-H",
                "Accept: application/vnd.github.raw+json",
                (
                    f"repos/{repository_name}/contents/{policy['gate_workflow_path']}"
                    f"?ref={policy['default_branch']}"
                ),
            ]
        )
        protection = _json_object(
            runner(
                [
                    "api",
                    (
                        f"repos/{repository_name}/branches/{policy['default_branch']}"
                        "/protection/required_status_checks"
                    ),
                ]
            ),
            f"branch protection {repository_name}",
        )
        reports.append(
            validate_target(
                policy=policy,
                target=target,
                repository=repository,
                variable_value=str(variable.get("value", "")),
                workflow=workflow,
                protection=protection,
                expected_gardener_ref=expected_gardener_ref,
                expected_authority_ref=expected_authority_ref,
            )
        )

    if selected_repositories and not reports:
        raise ReadinessError("no selected readiness targets matched the policy")
    return {
        "schema_version": "atlas-gardener/target-readiness-verification/v1",
        "status": "ready",
        "target_count": len(reports),
        "targets": reports,
        "provider_mutations": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--gardener-ref", required=True)
    parser.add_argument("--authority-ref", required=True)
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = collect_and_validate(
            policy_path=args.policy,
            expected_gardener_ref=args.gardener_ref,
            expected_authority_ref=args.authority_ref,
            selected_repositories=set(args.repository) or None,
        )
    except (OSError, UnicodeError, ReadinessError) as error:
        print(f"Gardener target readiness failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
