from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_gardener_target_readiness.py"
SPEC = importlib.util.spec_from_file_location("verify_gardener_target_readiness", SCRIPT)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class TargetReadinessVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {
            "expected_app_login": "atlas-gardener-w37-atlasreaper[bot]",
            "disabled_value": "false",
            "barrier_check": "Gardener native auto-merge barrier",
            "required_repository_settings": {
                "allow_squash_merge": True,
                "allow_auto_merge_at_rest": False,
            },
        }
        self.target = {
            "repository": "AtlasReaper311/specular-sonify",
            "required_checks": ["Worker configuration validation"],
        }
        self.workflow = "\n".join(
            [
                "uses: AtlasReaper311/atlas-gardener/.github/workflows/gardener-automerge-gate.yml@gardenerref",
                "expected_app_login: atlas-gardener-w37-atlasreaper[bot]",
                "authority_ref: authorityref",
                "enabled: ${{ vars.ATLAS_GARDENER_AUTOMERGE_ENABLED == 'true' && startsWith(github.event.pull_request.head.ref, 'gardener/') }}",
                "AUTOMERGE_ENABLED: ${{ vars.ATLAS_GARDENER_AUTOMERGE_ENABLED == 'true' && startsWith(github.event.pull_request.head.ref, 'gardener/') }}",
            ]
        )
        self.protection = {
            "contexts": [
                "Worker configuration validation",
                "Gardener native auto-merge barrier",
            ],
            "checks": [],
        }

    def test_accepts_ready_target(self) -> None:
        report = VERIFY.validate_target(
            policy=self.policy,
            target=self.target,
            repository={
                "full_name": self.target["repository"],
                "allow_squash_merge": True,
                "allow_auto_merge": False,
            },
            variable_value="false",
            workflow=self.workflow,
            protection=self.protection,
            expected_gardener_ref="gardenerref",
            expected_authority_ref="authorityref",
        )
        self.assertEqual("ready", report["status"])

    def test_rejects_missing_barrier(self) -> None:
        protection = copy.deepcopy(self.protection)
        protection["contexts"].remove("Gardener native auto-merge barrier")
        with self.assertRaisesRegex(VERIFY.ReadinessError, "missing required checks"):
            VERIFY.validate_target(
                policy=self.policy,
                target=self.target,
                repository={
                    "full_name": self.target["repository"],
                    "allow_squash_merge": True,
                    "allow_auto_merge": False,
                },
                variable_value="false",
                workflow=self.workflow,
                protection=protection,
                expected_gardener_ref="gardenerref",
                expected_authority_ref="authorityref",
            )

    def test_rejects_auto_merge_enabled_at_rest(self) -> None:
        with self.assertRaisesRegex(VERIFY.ReadinessError, "not disabled at rest"):
            VERIFY.validate_target(
                policy=self.policy,
                target=self.target,
                repository={
                    "full_name": self.target["repository"],
                    "allow_squash_merge": True,
                    "allow_auto_merge": True,
                },
                variable_value="false",
                workflow=self.workflow,
                protection=self.protection,
                expected_gardener_ref="gardenerref",
                expected_authority_ref="authorityref",
            )

    def test_rejects_unscoped_target_caller(self) -> None:
        workflow = self.workflow.replace("startsWith", "removedScope", 1)
        with self.assertRaisesRegex(VERIFY.ReadinessError, "scope both jobs"):
            VERIFY.validate_target(
                policy=self.policy,
                target=self.target,
                repository={
                    "full_name": self.target["repository"],
                    "allow_squash_merge": True,
                    "allow_auto_merge": False,
                },
                variable_value="false",
                workflow=workflow,
                protection=self.protection,
                expected_gardener_ref="gardenerref",
                expected_authority_ref="authorityref",
            )


if __name__ == "__main__":
    unittest.main()
