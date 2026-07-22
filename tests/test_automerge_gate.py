from __future__ import annotations

import importlib.util
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from atlas_gardener.automation import approval_marker, object_digest, read_object
from atlas_gardener.errors import SafetyRefusal

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/gardener_automerge_gate.py"
SPEC = importlib.util.spec_from_file_location("gardener_automerge_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class AutomergeGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.infra = Path(os.environ["ATLAS_GARDENER_INFRA_ROOT"]).resolve()
        cls.policy = read_object(
            cls.infra / "policy/gardener-automation.json", label="automation policy"
        )
        cls.coverage = read_object(
            cls.infra / "policy/gardener-github-app-coverage.json",
            label="coverage policy",
        )
        cls.now = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)

    def approval(self) -> dict:
        return {
            "schema_version": "atlas-control-plane/gardener-automation-approval/v1",
            "approval_id": "approval:sha256:" + "1" * 64,
            "remediation_key": "sha256:" + "2" * 64,
            "policy_digest": object_digest(self.policy),
            "coverage_digest": object_digest(self.coverage),
            "bundle_digest": "sha256:" + "3" * 64,
            "finding_fingerprint": "sha256:" + "4" * 64,
            "proposal_id": "proposal:sha256:" + "5" * 64,
            "plan_digest": "sha256:" + "6" * 64,
            "repository": "AtlasReaper311/atlas-dora",
            "classification": {
                "lifecycle": "production",
                "scope": "public",
                "provenance": "original",
            },
            "classification_fingerprint": "sha256:" + "7" * 64,
            "rule_id": "macos-metadata-ignore",
            "fixer": {"id": "macos-metadata-ignore", "version": "0.1.0"},
            "base_branch": "main",
            "base_sha": "8" * 40,
            "expected_head_sha": "9" * 40,
            "files": [
                {
                    "path": ".gitignore",
                    "mode": "100644",
                    "before_sha256": "a" * 64,
                    "after_sha256": "b" * 64,
                }
            ],
            "patch_digest": "sha256:" + "c" * 64,
            "risk_class": "low",
            "mode": "automerge-low-risk",
            "source_run": {
                "repository": "AtlasReaper311/atlas-dep-audit",
                "workflow": ".github/workflows/audit.yml",
                "run_id": "100",
                "run_attempt": 1,
                "commit": "d" * 40,
            },
            "controller_run": {
                "repository": "AtlasReaper311/atlas-gardener",
                "workflow": ".github/workflows/controller.yml",
                "run_id": "101",
                "run_attempt": 1,
                "commit": "e" * 40,
            },
            "issued_at": self.now.isoformat().replace("+00:00", "Z"),
            "expires_at": (self.now + timedelta(hours=24))
            .isoformat()
            .replace("+00:00", "Z"),
        }

    def pr(self) -> dict:
        approval = self.approval()
        return {
            "repository": "AtlasReaper311/atlas-dora",
            "number": 42,
            "state": "OPEN",
            "isDraft": False,
            "body": approval_marker(approval),
            "author": {"login": "atlas-gardener[bot]"},
            "headRefName": "gardener/macos-metadata-ignore-123456789abc",
            "headRefOid": approval["expected_head_sha"],
            "baseRefName": "main",
            "baseRefOid": approval["base_sha"],
            "commits": [{"oid": approval["expected_head_sha"]}],
            "statusCheckRollup": [
                {"name": "CI", "conclusion": "SUCCESS"},
                {"name": "Estate policy", "conclusion": "SUCCESS"},
            ],
        }

    def files(self) -> list[dict]:
        return [
            {
                "filename": ".gitignore",
                "status": "modified",
                "additions": 1,
                "deletions": 0,
                "patch": "@@ -1 +1,2 @@\n node_modules/\n+.DS_Store",
            }
        ]

    def validate(self, pr=None, files=None, checks=None):
        previous = os.environ.get("GITHUB_REPOSITORY")
        os.environ["GITHUB_REPOSITORY"] = "AtlasReaper311/atlas-dora"
        try:
            return GATE.validate_gate(
                pr=pr or self.pr(),
                files=self.files() if files is None else files,
                policy=self.policy,
                coverage=self.coverage,
                expected_app_login="atlas-gardener[bot]",
                required_checks=["CI", "Estate policy"] if checks is None else checks,
                now=self.now,
            )
        finally:
            if previous is None:
                os.environ.pop("GITHUB_REPOSITORY", None)
            else:
                os.environ["GITHUB_REPOSITORY"] = previous

    def test_successful_low_risk_ci_is_eligible(self) -> None:
        result = self.validate()
        self.assertTrue(result["eligible"])
        self.assertEqual("squash", result["merge_method"])
        self.assertEqual(["CI", "Estate policy"], result["required_checks"])

    def test_missing_checks_never_count_as_success(self) -> None:
        pr = self.pr()
        pr["statusCheckRollup"] = []
        with self.assertRaisesRegex(SafetyRefusal, "required checks are missing"):
            self.validate(pr=pr)
        with self.assertRaisesRegex(SafetyRefusal, "missing required-check configuration"):
            self.validate(checks=[])

    def test_failed_ci_prevents_merge(self) -> None:
        pr = self.pr()
        pr["statusCheckRollup"][0]["conclusion"] = "FAILURE"
        with self.assertRaisesRegex(SafetyRefusal, "required checks failed"):
            self.validate(pr=pr)

    def test_changed_head_and_extra_commit_fail_closed(self) -> None:
        pr = self.pr()
        pr["headRefOid"] = "f" * 40
        with self.assertRaisesRegex(SafetyRefusal, "head changed"):
            self.validate(pr=pr)
        pr = self.pr()
        pr["commits"].append({"oid": "f" * 40})
        with self.assertRaisesRegex(SafetyRefusal, "exactly one"):
            self.validate(pr=pr)

    def test_workflow_source_and_lockfile_paths_fail_closed(self) -> None:
        for path in (".github/workflows/ci.yml", "src/index.ts", "package-lock.json"):
            files = self.files()
            files[0]["filename"] = path
            with self.assertRaisesRegex(SafetyRefusal, "restricted to .gitignore"):
                self.validate(files=files)

    def test_deletion_and_unapproved_line_fail_closed(self) -> None:
        files = self.files()
        files[0]["deletions"] = 1
        with self.assertRaisesRegex(SafetyRefusal, "cannot delete"):
            self.validate(files=files)
        files = self.files()
        files[0]["patch"] += "\n+dist/"
        files[0]["additions"] = 2
        with self.assertRaisesRegex(SafetyRefusal, "unexpected line"):
            self.validate(files=files)

    def test_expired_and_changed_policy_fail_closed(self) -> None:
        pr = self.pr()
        approval = self.approval()
        approval["expires_at"] = (self.now - timedelta(seconds=1)).isoformat().replace(
            "+00:00", "Z"
        )
        pr["body"] = approval_marker(approval)
        with self.assertRaisesRegex(SafetyRefusal, "expired"):
            self.validate(pr=pr)
        pr = self.pr()
        approval = self.approval()
        approval["policy_digest"] = "sha256:" + "f" * 64
        pr["body"] = approval_marker(approval)
        with self.assertRaisesRegex(SafetyRefusal, "policy changed"):
            self.validate(pr=pr)


if __name__ == "__main__":
    unittest.main()
