from __future__ import annotations

import copy
import os
import unittest
from pathlib import Path

from atlas_gardener.automation import (
    automatic_merge_eligible,
    read_object,
    validate_fixer_plan_paths,
    validate_policy,
)
from atlas_gardener.errors import ContractError, SafetyRefusal


class ExpandedAutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = os.environ.get("ATLAS_GARDENER_TEST_INFRA_ROOT") or os.environ.get(
            "ATLAS_GARDENER_INFRA_ROOT"
        )
        if not root:
            raise RuntimeError("Atlas Infra test root is required")
        cls.infra = Path(root).resolve()
        cls.policy = read_object(
            cls.infra / "policy/gardener-automation.json", label="automation policy"
        )
        cls.coverage = read_object(
            cls.infra / "policy/gardener-github-app-coverage.json", label="coverage policy"
        )

    def plan(self, fixer_id: str, path: str) -> dict:
        return {
            "fixer": {"id": fixer_id, "version": "0.1.0"},
            "files": [
                {
                    "path": path,
                    "mode": "100644",
                    "action": "replace",
                    "after_text": "updated\n",
                    "before_text": "before\n",
                }
            ],
        }

    def test_committed_policy_accepts_exact_new_fixer_set(self) -> None:
        validated = validate_policy(copy.deepcopy(self.policy), copy.deepcopy(self.coverage))
        expected = {
            "npm-lock-security-remediation",
            "npm-security-update",
            "python-security-pin",
            "container-digest-pin",
        }
        self.assertEqual(
            expected,
            {
                fixer_id
                for fixer_id, item in validated["fixers"].items()
                if item["risk_class"] == "review-required" and fixer_id in expected
            },
        )

    def test_new_fixers_remain_review_required_in_automerge_evaluation(self) -> None:
        for fixer_id, path in (
            ("npm-lock-security-remediation", "package-lock.json"),
            ("npm-security-update", "package.json"),
            ("python-security-pin", "requirements.txt"),
            ("container-digest-pin", "Dockerfile"),
        ):
            eligible, reason = automatic_merge_eligible(
                self.plan(fixer_id, path), self.policy
            )
            self.assertFalse(eligible)
            self.assertEqual("fixer-review-required", reason)

    def test_selected_fixer_path_authority_is_enforced(self) -> None:
        with self.assertRaisesRegex(SafetyRefusal, "outside selected fixer authority"):
            validate_fixer_plan_paths(
                self.plan("python-security-pin", "package.json"), self.policy
            )

    def test_new_fixer_cannot_gain_automatic_merge(self) -> None:
        for fixer_id in ("npm-lock-security-remediation", "npm-security-update"):
            policy = copy.deepcopy(self.policy)
            policy["fixers"][fixer_id]["automatic_merge"] = True
            with self.assertRaisesRegex(ContractError, "cannot automatically merge"):
                validate_policy(policy, copy.deepcopy(self.coverage))

    def test_new_fixer_path_expansion_fails_closed(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["fixers"]["npm-lock-security-remediation"]["allowed_path_patterns"].append(
            r"^npm-shrinkwrap\.json$"
        )
        with self.assertRaisesRegex(ContractError, "path authority changed"):
            validate_policy(policy, copy.deepcopy(self.coverage))


if __name__ == "__main__":
    unittest.main()
