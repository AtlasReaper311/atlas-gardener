#!/usr/bin/env python3
"""Verify one completed Gardener rollout with exact-attempt and deployment evidence."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

ROLLOUT_PATH = Path(__file__).with_name("verify_gardener_rollout.py")
SPEC = importlib.util.spec_from_file_location("verify_gardener_rollout", ROLLOUT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {ROLLOUT_PATH}")
ROLLOUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROLLOUT)

DEPLOYMENT_CLASSES = {"automatic", "manual", "not-applicable"}


class AttemptAwareRunner:
    """Rewrite the generic jobs request to the exact Actions run attempt."""

    def __init__(
        self,
        *,
        target_repository: str,
        gate_run_id: int,
        run_attempt: int,
        runner: Callable[[Sequence[str]], str],
    ) -> None:
        self.target_repository = target_repository
        self.gate_run_id = gate_run_id
        self.run_attempt = run_attempt
        self.runner = runner

    def __call__(self, arguments: Sequence[str]) -> str:
        generic = [
            "api",
            f"repos/{self.target_repository}/actions/runs/{self.gate_run_id}/jobs",
        ]
        if list(arguments) == generic:
            return self.runner(
                [
                    "api",
                    (
                        f"repos/{self.target_repository}/actions/runs/"
                        f"{self.gate_run_id}/attempts/{self.run_attempt}/jobs?per_page=100"
                    ),
                ]
            )
        return self.runner(arguments)


def validate_deployment(
    *,
    classification: str,
    expected_merge_sha: str,
    deployment_run_id: int | None,
    deployment_run: dict[str, Any] | None,
) -> dict[str, Any]:
    if classification not in DEPLOYMENT_CLASSES:
        raise ROLLOUT.CANARY.VerificationError(
            f"unsupported deployment classification: {classification}"
        )
    if classification != "automatic":
        if deployment_run_id is not None or deployment_run is not None:
            raise ROLLOUT.CANARY.VerificationError(
                f"deployment evidence is not allowed for {classification}"
            )
        return {
            "classification": classification,
            "status": "not-required" if classification == "not-applicable" else "manual-boundary",
            "run_id": None,
        }

    if deployment_run_id is None or not isinstance(deployment_run, dict):
        raise ROLLOUT.CANARY.VerificationError(
            "automatic deployment classification requires one workflow run"
        )
    if deployment_run.get("id") != deployment_run_id:
        raise ROLLOUT.CANARY.VerificationError("deployment run ID changed")
    if deployment_run.get("event") != "push":
        raise ROLLOUT.CANARY.VerificationError("deployment was not triggered by a push")
    if deployment_run.get("head_sha") != expected_merge_sha:
        raise ROLLOUT.CANARY.VerificationError(
            "deployment run is not bound to the Gardener merge"
        )
    if str(deployment_run.get("status", "")).lower() != "completed":
        raise ROLLOUT.CANARY.VerificationError("deployment run did not complete")
    if str(deployment_run.get("conclusion", "")).lower() != "success":
        raise ROLLOUT.CANARY.VerificationError("deployment run did not succeed")
    return {
        "classification": classification,
        "status": "verified",
        "run_id": deployment_run_id,
        "head_sha": expected_merge_sha,
    }


def collect_and_validate_production_rollout(
    *,
    target_repository: str,
    pull_request_number: int,
    gate_run_id: int,
    expected_head_sha: str,
    expected_merge_sha: str,
    expected_app_login: str,
    expected_gardener_ref: str,
    expected_authority_ref: str,
    deployment_classification: str,
    deployment_run_id: int | None = None,
    runner: Callable[[Sequence[str]], str] = ROLLOUT.CANARY._run_gh,
) -> dict[str, Any]:
    gate_run = ROLLOUT.CANARY._gh_json(
        ["api", f"repos/{target_repository}/actions/runs/{gate_run_id}"],
        "gate run evidence",
        runner,
    )
    run_attempt = gate_run.get("run_attempt")
    if not isinstance(run_attempt, int) or run_attempt < 1:
        raise ROLLOUT.CANARY.VerificationError(
            "gate run does not expose a valid run_attempt"
        )

    report = ROLLOUT.collect_and_validate_rollout(
        target_repository=target_repository,
        pull_request_number=pull_request_number,
        gate_run_id=gate_run_id,
        expected_head_sha=expected_head_sha,
        expected_merge_sha=expected_merge_sha,
        expected_app_login=expected_app_login,
        expected_gardener_ref=expected_gardener_ref,
        expected_authority_ref=expected_authority_ref,
        runner=AttemptAwareRunner(
            target_repository=target_repository,
            gate_run_id=gate_run_id,
            run_attempt=run_attempt,
            runner=runner,
        ),
    )

    deployment_run = None
    if deployment_run_id is not None:
        deployment_run = ROLLOUT.CANARY._gh_json(
            ["api", f"repos/{target_repository}/actions/runs/{deployment_run_id}"],
            "deployment run evidence",
            runner,
        )
    report["schema_version"] = "atlas-gardener/production-rollout-verification/v1"
    report["gate_run_attempt"] = run_attempt
    report["deployment"] = validate_deployment(
        classification=deployment_classification,
        expected_merge_sha=expected_merge_sha,
        deployment_run_id=deployment_run_id,
        deployment_run=deployment_run,
    )
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
    parser.add_argument(
        "--deployment-classification",
        required=True,
        choices=sorted(DEPLOYMENT_CLASSES),
    )
    parser.add_argument("--deployment-run", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        report = collect_and_validate_production_rollout(
            target_repository=args.repository,
            pull_request_number=args.pull_request,
            gate_run_id=args.gate_run,
            expected_head_sha=args.head_sha,
            expected_merge_sha=args.merge_sha,
            expected_app_login=args.app_login,
            expected_gardener_ref=args.gardener_ref,
            expected_authority_ref=args.authority_ref,
            deployment_classification=args.deployment_classification,
            deployment_run_id=args.deployment_run,
        )
    except (ROLLOUT.CANARY.VerificationError, json.JSONDecodeError) as error:
        print(f"Gardener production rollout verification failed: {error}", file=sys.stderr)
        return 1

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
