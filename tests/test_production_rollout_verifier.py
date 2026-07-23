from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_gardener_production_rollout.py"
SPEC = importlib.util.spec_from_file_location("verify_gardener_production_rollout", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ProductionRolloutVerifierTests(unittest.TestCase):
    def test_attempt_runner_rewrites_generic_jobs_request(self) -> None:
        calls = []

        def runner(arguments):
            calls.append(list(arguments))
            return "{}"

        wrapped = VERIFY.AttemptAwareRunner(
            target_repository="AtlasReaper311/specular-sonify",
            gate_run_id=29972390426,
            run_attempt=4,
            runner=runner,
        )
        wrapped(
            [
                "api",
                "repos/AtlasReaper311/specular-sonify/actions/runs/29972390426/jobs",
            ]
        )
        self.assertEqual(
            [
                "api",
                (
                    "repos/AtlasReaper311/specular-sonify/actions/runs/"
                    "29972390426/attempts/4/jobs?per_page=100"
                ),
            ],
            calls[0],
        )

    def test_not_applicable_deployment_requires_no_run(self) -> None:
        report = VERIFY.validate_deployment(
            classification="not-applicable",
            expected_merge_sha="abc",
            deployment_run_id=None,
            deployment_run=None,
        )
        self.assertEqual("not-required", report["status"])

    def test_manual_deployment_requires_no_run(self) -> None:
        report = VERIFY.validate_deployment(
            classification="manual",
            expected_merge_sha="abc",
            deployment_run_id=None,
            deployment_run=None,
        )
        self.assertEqual("manual-boundary", report["status"])

    def test_automatic_deployment_binds_merge_sha(self) -> None:
        report = VERIFY.validate_deployment(
            classification="automatic",
            expected_merge_sha="abc",
            deployment_run_id=42,
            deployment_run={
                "id": 42,
                "event": "push",
                "head_sha": "abc",
                "status": "completed",
                "conclusion": "success",
            },
        )
        self.assertEqual("verified", report["status"])

    def test_rejects_evidence_for_not_applicable_deployment(self) -> None:
        with self.assertRaisesRegex(
            VERIFY.ROLLOUT.CANARY.VerificationError,
            "not allowed",
        ):
            VERIFY.validate_deployment(
                classification="not-applicable",
                expected_merge_sha="abc",
                deployment_run_id=42,
                deployment_run={"id": 42},
            )


if __name__ == "__main__":
    unittest.main()
